import html
import json
import logging
import threading
import time as _time
from datetime import timedelta

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

from netinsight.analytics.telemetry_handler import handle_telemetry_ingestion
from netinsight.analytics.topology import generate_topology_pyvis
from netinsight.config import settings
from netinsight.config.singletons import (
    get_analytics_engine,
    get_dse_engine,
    get_hmm_predictor,
    get_lp_optimizer,
    get_mdp_engine,
    get_traffic_classifier,
)
from netinsight.dashboard import speed_monitor
from netinsight.dashboard.models import (
    Agent,
    MetricRecord,
    PacketRecord,
    StateHistory,
    SystemSettings,
)
from netinsight.dashboard.views.utils import (
    apply_mdp_overrides as _apply_mdp_overrides,
)
from netinsight.dashboard.views.utils import (
    to_native_types as _to_native_types,
)
from netinsight.dashboard.views.utils import (
    validate_agent_token as _validate_agent_token,
)
from netinsight.prediction.markov import MarkovPredictor

logger = logging.getLogger(__name__)

# Centralized thread-safe singleton references
analytics_engine = get_analytics_engine()
optimizer = get_lp_optimizer()
dse_engine = get_dse_engine()
hmm_model = get_hmm_predictor()
hmm_predictor = hmm_model
classifier = get_traffic_classifier()
mdp_engine = get_mdp_engine()
markov_predictor = MarkovPredictor()


def _demo_telemetry_generator():
    """Background thread generating synthetic telemetry data for demo/demonstration mode."""
    import random
    import time as _time

    from django.db import close_old_connections
    close_old_connections()
    try:
        _time.sleep(3)  # Wait for Django to fully boot
        # Create a synthetic demo agent
        demo_agent, _ = Agent.objects.get_or_create(
            mac_address="de:mo:00:00:00:01",
            defaults={
                "hostname": "Demo-Agent-1",
                "device_type": "Demo Node",
                "vendor": "NetInsight Demo",
                "ip_address": "192.168.1.100"
            }
        )
        states = ["Normal", "Normal", "Normal", "Busy", "Busy", "Congested"]
        protocols = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
        while True:
            close_old_connections()
            now_ts = _time.time()
            demo_agent.cpu_usage = round(random.uniform(15, 65), 1)
            demo_agent.memory_usage = round(random.uniform(30, 75), 1)
            demo_agent.disk_usage = round(random.uniform(20, 50), 1)
            demo_agent.active_connections = random.randint(5, 40)
            demo_agent.bytes_sent = random.randint(100000, 5000000)
            demo_agent.bytes_recv = random.randint(500000, 15000000)
            demo_agent.last_seen = timezone.now()
            demo_agent.save()
            # Generate synthetic packets
            for _ in range(random.randint(3, 8)):
                PacketRecord.objects.create(
                    src_ip=f"192.168.1.{random.randint(2, 254)}",
                    dst_ip=f"10.0.0.{random.randint(1, 50)}",
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 53, 22, 8080]),
                    protocol=random.choice(protocols),
                    size=random.randint(64, 1500),
                    timestamp=now_ts,
                    ttl=random.choice([64, 128]),
                    agent=demo_agent
                )
            # Generate synthetic metric
            throughput = random.uniform(1e6, 8e6)
            MetricRecord.objects.create(
                timestamp=now_ts,
                throughput=throughput,
                packet_rate=random.uniform(50, 300),
                bandwidth_util=random.uniform(5, 60),
                latency=random.uniform(0.005, 0.080),
                packet_loss=random.uniform(0, 2.0)
            )
            # Generate synthetic state
            StateHistory.objects.create(
                timestamp=now_ts,
                network_state=random.choice(states),
                bandwidth_utilization=random.uniform(0.05, 0.60),
                packet_loss=random.uniform(0, 0.02),
                latency=random.uniform(0.005, 0.080)
            )
            # Prune old demo data (keep last 5 minutes)
            cutoff = now_ts - 300
            PacketRecord.objects.filter(timestamp__lt=cutoff, agent=demo_agent).delete()
            _time.sleep(3)
    except Exception as e:
        logger.error(f"Demo telemetry generator error: {e}", exc_info=True)
    finally:
        close_old_connections()

_demo_lock = threading.Lock()
_demo_thread_started = False

def ensure_monitor_started():
    """Starts demo telemetry generator if DEMO_MODE is active. Thread-safe check-and-set."""
    import threading
    global _demo_thread_started
    if settings.DEMO_MODE and not _demo_thread_started:
        with _demo_lock:
            if not _demo_thread_started:
                _demo_thread_started = True
                t = threading.Thread(target=_demo_telemetry_generator, daemon=True, name="DemoTelemetryGen")
                t.start()
                logger.info("[DEMO MODE] Synthetic telemetry generator started.")

# =====================================================================
# REST APIs for Agents Ingestion
# =====================================================================

@api_view(["POST"])
def api_register_agent(request):
    """API endpoint allowing new client endpoints to discover and register on Laptop 1."""
    if not _validate_agent_token(request):
        return Response({"error": "Unauthorized agent token"}, status=401)

    try:
        data = request.data
        mac_address = data.get("mac_address", "").lower().strip()
        hostname = html.escape(str(data.get("hostname", "Unknown-Host")).strip())
        device_type = html.escape(str(data.get("device_type", "Generic Node")).strip())
        vendor = html.escape(str(data.get("vendor", "Generic Vendor")).strip())
        ip_address = html.escape(str(data.get("ip_address", "0.0.0.0")).strip())

        if not mac_address:
            return Response({"error": "MAC Address is required for registration"}, status=400)

        # Agent identity keyed strictly by MAC address (hostname collisions are allowed)

        # Check if already registered
        agent, created = Agent.objects.get_or_create(
            mac_address=mac_address,
            defaults={
                "hostname": hostname,
                "device_type": device_type,
                "vendor": vendor,
                "ip_address": ip_address
            }
        )

        # If already existed, update its parameters
        if not created:
            agent.hostname = hostname
            agent.device_type = device_type
            agent.vendor = vendor
            agent.ip_address = ip_address
            agent.last_seen = timezone.now()
            agent.save()

        logger.info(f"Registered/updated agent: {agent.hostname} (MAC: {agent.mac_address})")
        return Response({"agent_id": str(agent.id), "status": "registered"}, status=200)

    except Exception as e:
        logger.error(f"Error registering agent: {e}", exc_info=True)
        return Response({"error": f"Internal server error: {e}"}, status=500)

@api_view(["POST"])
def api_agent_telemetry(request):
    """API endpoint receiving system telemetry and Scapy packet headers from agents."""
    if not _validate_agent_token(request):
        return Response({"error": "Unauthorized agent token"}, status=401)

    try:
        data = request.data
        agent_id = data.get("agent_id")
        stats = data.get("stats", {})
        packets = data.get("packets", [])

        if not agent_id:
            return Response({"error": "Missing agent_id"}, status=400)

        try:
            agent = Agent.objects.get(id=agent_id)
        except (Agent.DoesNotExist, ValueError):
            return Response({"error": "Invalid agent_id (Device not registered)"}, status=404)

        # Ingest packets and update system health stats asynchronously
        handle_telemetry_ingestion(agent, stats, packets)

        latest_state = StateHistory.objects.all().order_by("-timestamp").first()
        curr_state = latest_state.network_state if latest_state else "Normal"
        mdp_rec = mdp_engine.get_recommendation(curr_state)
        recommended_action = mdp_rec["recommended_action"]

        settings_obj = SystemSettings.objects.first()
        raw_priorities = settings_obj.lp_priorities if (settings_obj and settings_obj.lp_priorities) else settings.QOS_PRIORITIES
        raw_min = settings.QOS_MIN_BANDWIDTH
        raw_max = settings.QOS_MAX_BANDWIDTH
        capacity = speed_monitor.get_current_capacity()

        active_priorities = list(raw_priorities) if (raw_priorities and len(raw_priorities) >= 4) else [1.0, 2.0, 0.5, 3.0]
        # Scale bounds dynamically as percentages of current link capacity (relative to 100 Mbps baseline)
        scale_ratio = capacity / 100000000.0
        base_min = list(raw_min) if (raw_min and len(raw_min) >= 4) else [5e6, 15e6, 2e6, 10e6]
        base_max = list(raw_max) if (raw_max and len(raw_max) >= 4) else [40e6, 60e6, 30e6, 50e6]
        active_min_bounds = [float(val * scale_ratio) for val in base_min]
        active_max_bounds = [float(val * scale_ratio) for val in base_max]

        active_priorities, active_min_bounds, active_max_bounds = _apply_mdp_overrides(
            recommended_action, active_priorities, active_min_bounds, active_max_bounds
        )

        # Solve LP based on computed priorities and dynamic capacity bounds
        lp_result = optimizer.solve_allocation(active_priorities, active_min_bounds, active_max_bounds, capacity)
        allocations = lp_result.get("allocations") or []

        # Format allocation response in Mbps for client shaping enforcement
        enforced_qos = {
            "web_browsing_mbps": float(allocations[0] / 1e6) if len(allocations) > 0 else 5.0,
            "streaming_mbps": float(allocations[1] / 1e6) if len(allocations) > 1 else 15.0,
            "file_transfer_mbps": float(allocations[2] / 1e6) if len(allocations) > 2 else 2.0,
            "critical_services_mbps": float(allocations[3] / 1e6) if len(allocations) > 3 else 10.0,
            "recommended_policy": recommended_action
        }

        return Response({
            "status": "success",
            "enforced_qos": enforced_qos
        }, status=200)

    except Exception as e:
        logger.error(f"Error processing telemetry upload: {e}", exc_info=True)
        return Response({"error": f"Internal server error: {e}"}, status=500)

# =====================================================================
# Dashboard HTML Template Views
# =====================================================================

def api_live_metrics(request):
    """API endpoint returning active metrics, active agents online count, and DSE alerts."""
    try:
        latest = analytics_engine.get_latest_metrics()
        from datetime import timedelta
        now = timezone.now()
        active_cutoff = now - timedelta(seconds=15)
        active_agents = Agent.objects.filter(last_seen__gte=active_cutoff)
        active_devices_count = active_agents.count()
        latest["active_devices_count"] = active_devices_count
        latest["agents"] = [
            {
                "hostname": agent.hostname,
                "ip_address": agent.ip_address,
                "mac_address": agent.mac_address,
                "cpu_usage": agent.cpu_usage,
                "memory_usage": agent.memory_usage,
                "disk_usage": agent.disk_usage,
                "active_connections": agent.active_connections
            }
            for agent in active_agents
        ]

        # If no agents are online, override metrics to 0
        if active_devices_count == 0:
            latest["throughput"] = 0.0
            latest["packet_rate"] = 0.0
            latest["bandwidth_util"] = 0.0
            latest["latency"] = 0.0
            latest["packet_loss"] = 0.0

        # Determine network state dynamically
        state_record = StateHistory.objects.all().order_by("-timestamp").first()
        state_name = state_record.network_state if state_record and active_devices_count > 0 else "Normal"
        latest["network_state"] = state_name

        # Generate MDP recommendations
        latest["mdp_recommendation"] = mdp_engine.get_recommendation(state_name)

        # Generate DSE advisory alerts
        latest["dse_alerts"] = dse_engine.evaluate_decisions()

        latest["llm_active"] = bool(getattr(settings, "NVIDIA_API_KEY", None))
        latest["engine_name"] = "NVIDIA DeepSeek AI"
        latest["llm_latency_ms"] = getattr(classifier, "last_llm_latency_ms", 0.0)
        latest["llm_reasoning"] = getattr(classifier, "last_llm_reasoning", "")
        latest["llm_provider"] = "NVIDIA DeepSeek AI"
        latest["link_capacity_mbps"] = speed_monitor.get_current_capacity() / 1e6

        return JsonResponse(_to_native_types(latest))
    except Exception as e:
        logger.error(f"API live metrics error: {e}", exc_info=True)
        return JsonResponse({"error": "Unable to fetch live metrics"}, status=500)

def api_live_packets(request):
    """API endpoint returning latest 20 packet records as JSON."""
    try:
        # If no agents are currently online, clear the live packet log
        from datetime import timedelta
        now = timezone.now()
        active_cutoff = now - timedelta(seconds=15)
        active_agents_count = Agent.objects.filter(last_seen__gte=active_cutoff).count()
        if active_agents_count == 0:
            return JsonResponse({"packets": []})

        packets_qs = PacketRecord.objects.select_related("agent").order_by("-id")[:20]
        records = [
            {
                "id": r.id,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "src_port": r.src_port,
                "dst_port": r.dst_port,
                "protocol": r.protocol,
                "size": r.size,
                "timestamp": r.timestamp,
                "ttl": r.ttl,
                "agent_hostname": r.agent.hostname if r.agent else "Unknown"
            }
            for r in packets_qs
        ]
        return JsonResponse({"packets": _to_native_types(records)})
    except Exception as e:
        logger.error(f"API packets error: {e}", exc_info=True)
        return JsonResponse({"packets": [], "error": str(e)}, status=500)
def api_topology_graph(request):
    """Serves the interactive PyVis graph HTML directly for iframe inclusion."""
    html_graph = generate_topology_pyvis()
    return HttpResponse(html_graph, content_type="text/html")


def api_stream_metrics(request):
    """Server-Sent Events (SSE) real-time streaming endpoint for sub-second live metrics."""
    from django.http import StreamingHttpResponse

    def event_stream():
        while True:
            try:
                latest = analytics_engine.get_latest_metrics()
                now = timezone.now()
                active_cutoff = now - timedelta(seconds=15)
                active_agents = Agent.objects.filter(last_seen__gte=active_cutoff)
                active_devices_count = active_agents.count()

                if active_devices_count == 0:
                    latest["throughput"] = 0.0
                    latest["packet_rate"] = 0.0
                    latest["bandwidth_util"] = 0.0
                    latest["latency"] = 0.0
                    latest["packet_loss"] = 0.0

                state_record = StateHistory.objects.all().order_by("-timestamp").first()
                state_name = state_record.network_state if state_record and active_devices_count > 0 else "Normal"
                latest["network_state"] = state_name
                latest["active_devices_count"] = active_devices_count
                latest["mdp_recommendation"] = mdp_engine.get_recommendation(state_name)

                payload = json.dumps(_to_native_types(latest))
                yield f"data: {payload}\n\n"
                _time.sleep(1.0)
            except Exception as e:
                logger.error(f"SSE stream error: {e}")
                _time.sleep(1.0)

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response

