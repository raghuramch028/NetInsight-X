import hmac
import html
import logging
import threading
from typing import Any

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
import numpy as np
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response

import netinsight.dashboard.speed_monitor as speed_monitor
from netinsight.analytics.engine import AnalyticsEngine
from netinsight.analytics.telemetry_handler import handle_telemetry_ingestion
from netinsight.analytics.topology import generate_topology_pyvis
from netinsight.classification.classifier import get_shared_classifier
from netinsight.config import settings
from netinsight.dashboard.models import (
    Agent,
    MetricRecord,
    PacketRecord,
    StateHistory,
    SystemSettings,
)
from netinsight.optimization.solver import BandwidthOptimizer
from netinsight.prediction.dse import DecisionSupportEngine
from netinsight.prediction.hmm import get_shared_hmm
from netinsight.prediction.markov import MarkovPredictor
from netinsight.prediction.mdp import MDPRecommendationEngine

logger = logging.getLogger(__name__)

# Singleton solvers and classifiers instances
analytics_engine = AnalyticsEngine()
optimizer = BandwidthOptimizer()

hmm_predictor = get_shared_hmm()
markov_predictor = MarkovPredictor()
mdp_engine = MDPRecommendationEngine()
classifier = get_shared_classifier()
dse_engine = DecisionSupportEngine()

def _to_native_types(obj: Any) -> Any:
    """Recursively converts numpy/pandas scalars to plain Python types for JSON serialization."""
    if isinstance(obj, dict):
        return {k: _to_native_types(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_to_native_types(v) for v in obj]
    if isinstance(obj, (np.generic,)):
        return obj.item()
    return obj

def _check_dashboard_auth(request):
    """Returns HttpResponse 401 if NETINSIGHT_REQUIRE_AUTH is enabled and user is unauthenticated."""
    if getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False) and (not request.user or not request.user.is_authenticated):
        return JsonResponse({"error": "Authentication required to access dashboard endpoints"}, status=401)
    return None

def _validate_agent_token(request) -> bool:
    """Validates optional X-Agent-Token header if NETINSIGHT_AGENT_TOKEN is configured.
    Uses hmac.compare_digest for constant-time comparison to prevent timing attacks."""
    token = getattr(settings, "NETINSIGHT_AGENT_TOKEN", None)
    if token:
        auth_header = request.headers.get("X-Agent-Token") or request.META.get("HTTP_X_AGENT_TOKEN")
        if not auth_header or not hmac.compare_digest(str(auth_header), str(token)):
            return False
    return True

def _apply_mdp_overrides(recommended_action: str, priorities: list, min_bounds: list, max_bounds: list) -> tuple:
    """Applies MDP-driven priority/bounds adjustments based on recommended action.
    Returns (adjusted_priorities, adjusted_min_bounds, adjusted_max_bounds)."""
    p = list(priorities)
    m = list(min_bounds)
    x = list(max_bounds)
    if recommended_action == "Prioritize Critical Services" and len(p) >= 4:
        p[3] = float(p[3] * 2.0)
        m[3] = float(m[3] * 1.5)
        p[2] = float(p[2] * 0.5)
    elif recommended_action == "Reroute Traffic" and len(p) >= 3:
        p[0] = float(p[0] * 1.5)
        p[1] = float(p[1] * 0.5)
        p[2] = float(p[2] * 0.2)
    return p, m, x

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

