import html
import json
import logging
import os
import re
import threading
import time as _time
from datetime import timedelta

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
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
    PacketRecord,
    StateHistory,
    SystemSettings,
)
from netinsight.dashboard.views.utils import (
    apply_mdp_overrides as _apply_mdp_overrides,
)
from netinsight.dashboard.views.utils import (
    require_dashboard_auth as _require_dashboard_auth,
)
from netinsight.dashboard.views.utils import (
    to_native_types as _to_native_types,
)
from netinsight.dashboard.views.utils import (
    validate_agent_token as _validate_agent_token,
)
from netinsight.prediction.markov import MarkovPredictor

logger = logging.getLogger(__name__)

_MAC_ADDRESS_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _is_valid_mac(mac: str) -> bool:
    return bool(_MAC_ADDRESS_RE.match(mac))


def _clean_ip_or_default(raw_ip: str, default: str = "0.0.0.0") -> str:
    """Validates an IP address string, falling back to a safe default on malformed input rather
    than writing an unvalidated string into the ip_address field (GenericIPAddressField isn't
    enforced by save()/bulk_create() — only by full_clean(), which this API doesn't call)."""
    candidate = (raw_ip or "").strip()
    try:
        validate_ipv46_address(candidate)
        return candidate
    except ValidationError:
        return default


# Centralized thread-safe singleton references
analytics_engine = get_analytics_engine()
optimizer = get_lp_optimizer()
dse_engine = get_dse_engine()
hmm_model = get_hmm_predictor()
hmm_predictor = hmm_model
classifier = get_traffic_classifier()
mdp_engine = get_mdp_engine()
markov_predictor = MarkovPredictor()

# =====================================================================
# Health Check
# =====================================================================

def api_health_check(request):
    """Lightweight liveness/readiness probe for load balancers, container orchestrators, or
    uptime monitoring. Deliberately not gated by dashboard or agent auth (standard practice for
    health endpoints) and returns no sensitive information — only basic DB connectivity status."""
    from django.db import connections
    from django.db.utils import Error as DjangoDBError

    db_ok = True
    try:
        connections["default"].cursor()
    except DjangoDBError:
        db_ok = False

    return JsonResponse(
        {"status": "ok" if db_ok else "degraded", "database": db_ok},
        status=200 if db_ok else 503,
    )


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
        mac_address = str(data.get("mac_address", "")).lower().strip()
        # Escaped THEN truncated to the model's max_length: SQLite doesn't enforce CharField
        # max_length at the DB level, but Postgres (this project's optional production backend,
        # via DATABASE_URL) enforces varchar(n) and would raise a hard DB error on overflow
        # since this endpoint doesn't call Django's full_clean() validators.
        hostname = html.escape(str(data.get("hostname", "Unknown-Host")).strip())[:255]
        device_type = html.escape(str(data.get("device_type", "Generic Node")).strip())[:100]
        vendor = html.escape(str(data.get("vendor", "Generic Vendor")).strip())[:255]
        ip_address = html.escape(_clean_ip_or_default(str(data.get("ip_address", "0.0.0.0"))))

        if not mac_address:
            return Response({"error": "MAC Address is required for registration"}, status=400)

        if not _is_valid_mac(mac_address):
            return Response(
                {"error": "mac_address must be a valid MAC address, e.g. 'aa:bb:cc:dd:ee:ff'"},
                status=400,
            )

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
        # Log full detail server-side; never echo raw exception text (potential internal
        # implementation/DB detail) back to an unauthenticated-by-default caller.
        logger.error(f"Error registering agent: {e}", exc_info=True)
        return Response({"error": "Internal server error while registering agent."}, status=500)

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
        return Response({"error": "Internal server error while processing telemetry."}, status=500)

# =====================================================================
# Dashboard HTML Template Views
# =====================================================================

@_require_dashboard_auth
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

        # Determine network state dynamically (enforce 30s freshness)
        now_ts = _time.time()
        state_record = StateHistory.objects.all().order_by("-timestamp").first()
        is_fresh_state = state_record and (now_ts - state_record.timestamp) < 30.0
        state_name = state_record.network_state if is_fresh_state and active_devices_count > 0 else "Normal"
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

@_require_dashboard_auth
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
@_require_dashboard_auth
def api_topology_graph(request):
    """Serves the interactive PyVis graph HTML directly for iframe inclusion."""
    html_graph = generate_topology_pyvis()
    return HttpResponse(html_graph, content_type="text/html")


# --- SSE concurrency guard -----------------------------------------------------------------
# api_stream_metrics() holds a request thread/worker open for as long as the browser tab stays
# on the page. On a synchronous WSGI server (gunicorn's default sync worker class, which is what
# this project's README documents), an unbounded number of concurrent SSE connections can
# starve every worker, making the entire server (including agent ingestion) unresponsive.
# This bounds concurrent streams and caps each stream's lifetime so a worker is always
# eventually reclaimed; EventSource clients auto-reconnect after the stream closes.
_SSE_MAX_CONNECTIONS = int(os.environ.get("NETINSIGHT_MAX_SSE_CONNECTIONS", "4"))
_SSE_MAX_DURATION_SECONDS = int(os.environ.get("NETINSIGHT_SSE_MAX_DURATION", "300"))
_sse_semaphore = threading.BoundedSemaphore(_SSE_MAX_CONNECTIONS)


@_require_dashboard_auth
async def api_stream_metrics(request):
    """Server-Sent Events (SSE) real-time streaming endpoint for sub-second live metrics.

    This is a genuine `async def` Django view (native async view support, Django 4.1+): under
    an ASGI server (uvicorn/daphne — see README "Production Deployment Notes"), each connection
    parks on `await asyncio.sleep(1.0)` between updates instead of blocking an OS thread for its
    entire lifetime, so many concurrent viewers no longer pin one worker each. Under a plain
    WSGI server, Django's `async_to_sync` adapter still runs this correctly (safe fallback,
    identical behavior/bound to before) — the concurrency win specifically requires ASGI.

    Concurrency is additionally bounded by NETINSIGHT_MAX_SSE_CONNECTIONS (default 4) and each
    stream self-terminates after NETINSIGHT_SSE_MAX_DURATION seconds (default 300) as
    defense-in-depth regardless of deployment mode — a slow/leaked client still can't hold a
    slot forever, and callers beyond the cap get a 503 with Retry-After instead of hanging.
    """
    import asyncio

    from asgiref.sync import sync_to_async
    from django.http import StreamingHttpResponse

    if not _sse_semaphore.acquire(blocking=False):
        logger.warning(
            f"SSE connection limit reached ({_SSE_MAX_CONNECTIONS}). Rejecting new stream connection."
        )
        response = JsonResponse(
            {"error": "Live stream capacity reached. Retry shortly or use polling APIs instead."},
            status=503,
        )
        response["Retry-After"] = "5"
        return response

    get_latest_metrics_async = sync_to_async(analytics_engine.get_latest_metrics, thread_sensitive=False)

    async def event_stream():
        stream_start = _time.time()
        try:
            while True:
                if (_time.time() - stream_start) > _SSE_MAX_DURATION_SECONDS:
                    logger.info("SSE stream reached max duration; closing to free the connection slot.")
                    return

                try:
                    latest = await get_latest_metrics_async()
                    now = timezone.now()
                    active_cutoff = now - timedelta(seconds=15)
                    active_devices_count = await Agent.objects.filter(last_seen__gte=active_cutoff).acount()

                    if active_devices_count == 0:
                        latest["throughput"] = 0.0
                        latest["packet_rate"] = 0.0
                        latest["bandwidth_util"] = 0.0
                        latest["latency"] = 0.0
                        latest["packet_loss"] = 0.0

                    now_ts = _time.time()
                    state_record = await StateHistory.objects.all().order_by("-timestamp").afirst()
                    is_fresh_state = state_record and (now_ts - state_record.timestamp) < 30.0
                    state_name = (
                        state_record.network_state if is_fresh_state and active_devices_count > 0 else "Normal"
                    )
                    latest["network_state"] = state_name
                    latest["active_devices_count"] = active_devices_count
                    # CPU-only (numpy value iteration over a fixed 5-state MDP) — no I/O, safe to
                    # call directly without sync_to_async.
                    latest["mdp_recommendation"] = mdp_engine.get_recommendation(state_name)

                    payload = json.dumps(_to_native_types(latest))
                    yield f"data: {payload}\n\n"
                    await asyncio.sleep(1.0)
                except Exception as e:
                    logger.error(f"SSE stream error: {e}")
                    await asyncio.sleep(1.0)
        finally:
            _sse_semaphore.release()

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


@_require_dashboard_auth
@api_view(["POST"])
def api_trigger_scenario(request):
    """API endpoint to trigger a presentation demo scenario (Scenario 1, 2, or 3)."""
    try:
        from netinsight.dashboard.demo_scenarios import trigger_scenario
        data = request.data or {}
        scenario_id = int(data.get("scenario_id", 1))
        result = trigger_scenario(scenario_id)
        return Response({"status": "success", "scenario": _to_native_types(result)}, status=200)
    except Exception as e:
        logger.error(f"Error triggering demo scenario: {e}", exc_info=True)
        return Response({"error": str(e)}, status=500)


