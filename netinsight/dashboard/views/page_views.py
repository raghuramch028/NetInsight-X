import hmac
import logging
import threading
from datetime import timedelta
from typing import Any

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
import numpy as np
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.clickjacking import xframe_options_exempt

import netinsight.dashboard.speed_monitor as speed_monitor
from netinsight.analytics.engine import AnalyticsEngine
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

def index_view(request):
    """Renders the main Live Monitor and System Dashboard page."""
    ensure_monitor_started()
    # Retrieve system settings
    settings_obj = SystemSettings.objects.first()
    if not settings_obj:
        settings_obj = SystemSettings.objects.create()

    # Query active agents dynamically
    now = timezone.now()
    active_threshold = timedelta(seconds=15)

    agents_all = Agent.objects.all()
    active_agents = []

    for agent in agents_all:
        is_online = (now - agent.last_seen) < active_threshold
        active_agents.append({
            "hostname": agent.hostname,
            "mac_address": agent.mac_address,
            "ip_address": agent.ip_address,
            "device_type": agent.device_type,
            "vendor": agent.vendor,
            "cpu_usage": agent.cpu_usage,
            "memory_usage": agent.memory_usage,
            "disk_usage": agent.disk_usage,
            "active_connections": agent.active_connections,
            "bytes_sent_mb": agent.bytes_sent / 1048576.0,
            "bytes_recv_mb": agent.bytes_recv / 1048576.0,
            "is_online": is_online,
            "last_seen": agent.last_seen
        })

    online_agents_count = sum(1 for a in active_agents if a["is_online"])

    # Get latest calculated network-wide metrics
    latest = analytics_engine.get_latest_metrics()

    # If no agents are online, force metrics to 0
    if online_agents_count == 0:
        latest["throughput"] = 0.0
        latest["packet_rate"] = 0.0
        latest["bandwidth_util"] = 0.0
        latest["latency"] = 0.0
        latest["packet_loss"] = 0.0

    latest["throughput_mbps"] = latest["throughput"] / 1e6
    latest["latency_ms"] = latest["latency"] * 1000.0

    # Retrieve current network state
    state_record = StateHistory.objects.all().order_by("-timestamp").first()
    state_name = state_record.network_state if state_record and online_agents_count > 0 else "Normal"

    # Solve MDP Recommendation Engine
    mdp_rec = mdp_engine.get_recommendation(state_name)

    # Solve DSE actionable alert cards
    dse_alerts = dse_engine.evaluate_decisions()

    context = {
        "refresh_interval": settings.DASHBOARD_REFRESH_INTERVAL,
        "latest": latest,
        "current_state": state_name,
        "mdp_rec": mdp_rec,
        "agents": active_agents,
        "agents_count": len(active_agents),
        "online_agents_count": sum(1 for a in active_agents if a["is_online"]),
        "dse_alerts": dse_alerts,
        "settings": settings_obj,
        "link_capacity_mbps": speed_monitor.get_current_capacity() / 1e6,
    }
    return render(request, "dashboard/index.html", context)

def analytics_view(request):
    """Renders the Traffic Analytics page."""
    summary = analytics_engine.get_general_summary(window_seconds=60)
    protocol_dist = analytics_engine.get_protocol_distribution(window_seconds=60)
    top_consumers = analytics_engine.get_top_consumers(limit=5, window_seconds=60)

    consumers_list = top_consumers.to_dict(orient="records") if not top_consumers.empty else []
    for client in consumers_list:
        client["total_mb"] = client["total_bytes"] / 1048576.0

    protocols_list = protocol_dist.to_dict(orient="records") if not protocol_dist.empty else []

    context = {
        "summary": summary,
        "consumers": consumers_list,
        "protocols": protocols_list,
        "link_capacity_mbps": settings.LINK_CAPACITY / 1e6
    }
    return render(request, "dashboard/analytics.html", context)

@xframe_options_exempt
def prediction_view(request):
    """Renders HMM transitions matrix, baseline Markov forecasts, and MDP value recommendations."""
    # Query latest state history
    state_record = StateHistory.objects.all().order_by("-timestamp").first()
    curr_state = state_record.network_state if state_record else "Normal"

    # Solve HMM Forecasts
    hmm_1step = hmm_predictor.predict_state_forecast(curr_state, steps=1)
    hmm_3step = hmm_predictor.predict_state_forecast(curr_state, steps=3)

    # Solve baseline Markov Predictor forecast for comparative benchmark
    markov_1step = markov_predictor.predict_state_distribution(curr_state, k_steps=1)

    # Solve MDP Value iteration recommendation
    mdp_rec = mdp_engine.get_recommendation(curr_state)

    # Build matrix probabilities mapping
    states = ["Normal", "Busy", "Congested", "Under Attack", "Recovering"]
    state_keys = ["Normal", "Busy", "Congested", "Under_Attack", "Recovering"]
    matrix_rows = []
    matrix_data = hmm_predictor.estimate_transition_matrix()

    for i, s_from in enumerate(states):
        row_probs = {state_keys[j]: f"{matrix_data[i][j]*100:.1f}%" for j in range(5)}
        row_probs["from"] = s_from
        matrix_rows.append(row_probs)

    context = {
        "current_state": curr_state,
        "matrix_rows": matrix_rows,
        "pred_1step": {k: v * 100.0 for k, v in hmm_1step["forecast"].items()},
        "pred_3step": {k: v * 100.0 for k, v in hmm_3step["forecast"].items()},
        "markov_baseline": markov_1step.get("prediction", {}),
        "mdp": mdp_rec,
        "gamma": settings.MDP_DISCOUNT_FACTOR,
        "using_default_matrix": (StateHistory.objects.count() < 2)
    }
    return render(request, "dashboard/prediction.html", context)

def optimization_view(request):
    """Solves Linear Programming bandwidth optimization QoS and verifies KKT."""
    settings_obj = SystemSettings.objects.first()
    if not settings_obj:
        settings_obj = SystemSettings.objects.create()

    # Read priorities and limits from dynamically configured settings model
    priorities = settings_obj.lp_priorities
    if not priorities:
        priorities = settings.QOS_PRIORITIES
        settings_obj.lp_priorities = priorities
        settings_obj.save()

    min_bounds = settings.QOS_MIN_BANDWIDTH
    max_bounds = settings.QOS_MAX_BANDWIDTH
    capacity = speed_monitor.get_current_capacity()

    if request.method == "POST":
        try:
            raw_priorities = request.POST.getlist("priorities")
            raw_min_bounds = request.POST.getlist("min_bounds")
            raw_max_bounds = request.POST.getlist("max_bounds")
            raw_capacity = request.POST.get("capacity")

            if len(raw_priorities) != 4 or len(raw_min_bounds) != 4 or len(raw_max_bounds) != 4:
                raise ValueError("Optimization requires exactly 4 QoS classes.")

            priorities = [max(0.1, float(x)) for x in raw_priorities]
            min_bounds = [max(0.0, float(x) * 1e6) for x in raw_min_bounds]
            max_bounds = [max(0.0, float(x) * 1e6) for x in raw_max_bounds]
            capacity = max(1e6, float(raw_capacity) * 1e6)

            # Save priorities dynamically
            settings_obj.lp_priorities = priorities
            settings_obj.save()
        except Exception as e:
            logger.error(f"Error loading manual custom LP settings: {e}")
    else:
        # Scale bounds dynamically on GET load relative to current dynamic capacity
        scale_ratio = capacity / 100000000.0
        min_bounds = [float(val * scale_ratio) for val in min_bounds]
        max_bounds = [float(val * scale_ratio) for val in max_bounds]

    # Fetch current network state and apply MDP dynamic adjustments
    latest_state = StateHistory.objects.all().order_by("-timestamp").first()
    curr_state = latest_state.network_state if latest_state else "Normal"
    mdp_rec = mdp_engine.get_recommendation(curr_state)
    recommended_action = mdp_rec["recommended_action"]

    active_priorities = list(priorities)
    active_min_bounds = list(min_bounds)
    active_max_bounds = list(max_bounds)

    active_priorities, active_min_bounds, active_max_bounds = _apply_mdp_overrides(
        recommended_action, active_priorities, active_min_bounds, active_max_bounds
    )
    if recommended_action != "Reallocate Bandwidth":
        logger.info(f"MDP Optimization Override active: {recommended_action}.")

    classes = ["Web Browsing", "Streaming", "File Transfer", "Critical Services"]

    # Solve LP using dynamically adjusted weights and bounds
    result = optimizer.solve_allocation(active_priorities, active_min_bounds, active_max_bounds, capacity)

    # Map allocations back for template rendering
    raw_allocations = result.get("allocations") or [0.0] * len(classes)
    allocation_mbps = [x / 1e6 for x in raw_allocations]
    mapped_allocations = []
    for idx, name in enumerate(classes):
        mapped_allocations.append({
            "class": name,
            "priority": active_priorities[idx],
            "min_req": active_min_bounds[idx] / 1e6,
            "max_lim": active_max_bounds[idx] / 1e6,
            "allocated": allocation_mbps[idx]
        })

    # Check online agents count
    now = timezone.now()
    active_threshold = timedelta(seconds=15)
    online_agents_count = Agent.objects.filter(last_seen__gte=now - active_threshold).count()

    context = {
        "status": result["status"],
        "utility": (result["utility"] or 0.0) / 1e6,
        "mapped_allocations": mapped_allocations,
        "kkt": result["kkt_results"],
        "total_capacity_mbps": capacity / 1e6,
        "input_priorities": active_priorities,
        "input_min_bounds": [x / 1e6 for x in active_min_bounds],
        "input_max_bounds": [x / 1e6 for x in active_max_bounds],
        "online_agents_count": online_agents_count,
        "mdp_rec": mdp_rec
    }
    return render(request, "dashboard/optimization.html", context)

def classification_view(request):
    """Renders SVM Classifier threat audit tables and live packet predictions."""
    packets_qs = PacketRecord.objects.all().select_related("agent").order_by("-timestamp")[:50]

    packets_list = []
    for pkt in packets_qs:
        rec = {
            "src_ip": pkt.src_ip,
            "dst_ip": pkt.dst_ip,
            "src_port": pkt.src_port,
            "dst_port": pkt.dst_port,
            "protocol": pkt.protocol,
            "size": pkt.size,
            "timestamp": pkt.timestamp,
            "ttl": pkt.ttl,
            "agent_hostname": pkt.agent.hostname
        }
        # Classify threat label dynamically
        rec["classification"] = classifier.classify_packet(rec)
        packets_list.append(rec)

    stats = classifier.get_model_stats()

    llm_active = bool(getattr(settings, "NVIDIA_API_KEY", None) or getattr(settings, "GEMINI_API_KEY", None))

    context = {
        "model_loaded": classifier.clf is not None,
        "stats": stats,
        "recent_packets": packets_list,
        "llm_active": llm_active,
        "engine_name": getattr(classifier, "last_engine_used", "XGBoost"),
        "llm_latency_ms": getattr(classifier, "last_llm_latency_ms", 0.0),
        "llm_reasoning": getattr(classifier, "last_llm_reasoning", ""),
        "llm_provider": getattr(classifier, "last_llm_provider", ""),
    }
    return render(request, "dashboard/classification.html", context)

# =====================================================================
# Settings view
# =====================================================================

def settings_view(request):
    """Configures dynamic system thresholds without code modifications."""
    settings_obj = SystemSettings.objects.first()
    if not settings_obj:
        settings_obj = SystemSettings.objects.create()

    if request.method == "POST":
        try:
            settings_obj.bandwidth_threshold = float(request.POST.get("bandwidth_threshold", 0.75))
            settings_obj.loss_threshold = float(request.POST.get("loss_threshold", 0.05))
            settings_obj.latency_threshold = float(request.POST.get("latency_threshold", 0.15))
            settings_obj.svm_confidence_threshold = float(request.POST.get("svm_confidence_threshold", 0.80))
            settings_obj.save()
            mdp_engine.invalidate_cache()
            logger.info("Successfully updated SystemSettings thresholds dynamically.")
            return redirect("dashboard:index")
        except Exception as e:
            logger.error(f"Failed to save dynamic thresholds: {e}")
            context = {"settings": settings_obj, "error_message": f"Failed to save settings: {e}"}
            return render(request, "dashboard/settings.html", context)

    context = {
        "settings": settings_obj
    }
    return render(request, "dashboard/settings.html", context)

# =====================================================================
# Reports & Plots
# =====================================================================

