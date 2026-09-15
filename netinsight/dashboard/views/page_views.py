import logging
from datetime import timedelta

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
from django.shortcuts import redirect, render
from django.utils import timezone

from netinsight.config import settings
from netinsight.config.singletons import (
    get_analytics_engine,
    get_dse_engine,
    get_lp_optimizer,
    get_traffic_classifier,
)
from netinsight.dashboard import speed_monitor
from netinsight.dashboard.demo_data import ensure_monitor_started
from netinsight.dashboard.models import Agent, PacketRecord, SystemSettings
from netinsight.dashboard.views.utils import (
    require_dashboard_auth as _require_dashboard_auth,
)

logger = logging.getLogger(__name__)

# Centralized thread-safe singleton references
analytics_engine = get_analytics_engine()
optimizer = get_lp_optimizer()
classifier = get_traffic_classifier()
dse_engine = get_dse_engine()


@_require_dashboard_auth
def index_view(request):
    """Renders the main Live Monitor and System Dashboard page."""
    ensure_monitor_started()
    settings_obj = SystemSettings.objects.first()
    if not settings_obj:
        settings_obj = SystemSettings.objects.create()

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

    latest = analytics_engine.get_latest_metrics()

    if online_agents_count == 0:
        latest["throughput"] = 0.0
        latest["packet_rate"] = 0.0
        latest["bandwidth_util"] = 0.0
        latest["latency"] = 0.0
        latest["packet_loss"] = 0.0

    latest["throughput_mbps"] = latest["throughput"] / 1e6
    latest["latency_ms"] = latest["latency"] * 1000.0

    dse_alerts = dse_engine.evaluate_decisions()

    context = {
        "refresh_interval": settings.DASHBOARD_REFRESH_INTERVAL,
        "latest": latest,
        "agents": active_agents,
        "agents_count": len(active_agents),
        "online_agents_count": online_agents_count,
        "dse_alerts": dse_alerts,
        "settings": settings_obj,
        "link_capacity_mbps": speed_monitor.get_current_capacity() / 1e6,
    }
    return render(request, "dashboard/index.html", context)


@_require_dashboard_auth
def optimization_view(request):
    """Solves Linear Programming bandwidth optimization QoS and verifies KKT."""
    settings_obj = SystemSettings.objects.first()
    if not settings_obj:
        settings_obj = SystemSettings.objects.create()

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

            settings_obj.lp_priorities = priorities
            settings_obj.save()
        except Exception as e:
            logger.error(f"Error loading manual custom LP settings: {e}")
    else:
        scale_ratio = capacity / 100000000.0
        min_bounds = [float(val * scale_ratio) for val in min_bounds]
        max_bounds = [float(val * scale_ratio) for val in max_bounds]

    active_priorities = list(priorities)
    active_min_bounds = list(min_bounds)
    active_max_bounds = list(max_bounds)

    classes = ["Web Browsing", "Streaming", "File Transfer", "Critical Services"]

    result = optimizer.solve_allocation(active_priorities, active_min_bounds, active_max_bounds, capacity)

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
    }
    return render(request, "dashboard/optimization.html", context)


@_require_dashboard_auth
def classification_view(request):
    """Renders heuristic/LLM threat classifier audit tables and live packet predictions."""
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
        rec["classification"] = getattr(pkt, "classification", None) or classifier._classify_rule_based(rec)
        packets_list.append(rec)

    llm_active = bool(getattr(settings, "NVIDIA_API_KEY", None))

    context = {
        "recent_packets": packets_list,
        "llm_active": llm_active,
        "engine_name": "NVIDIA DeepSeek AI",
        "model_name": getattr(settings, "NVIDIA_MODEL_NAME", "deepseek-ai/deepseek-r1"),
        "llm_latency_ms": getattr(classifier, "last_llm_latency_ms", 0.0),
        "llm_reasoning": getattr(classifier, "last_llm_reasoning", ""),
        "llm_confidence": getattr(classifier, "last_llm_confidence", None),
        "llm_provider": "NVIDIA DeepSeek AI",
    }
    return render(request, "dashboard/classification.html", context)


@_require_dashboard_auth
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
            settings_obj.llm_confidence_threshold = float(request.POST.get("llm_confidence_threshold", 0.80))
            settings_obj.save()
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
