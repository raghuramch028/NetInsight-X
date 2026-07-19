import base64
import io
import csv
import json
import logging
import time
from datetime import timedelta
from typing import Any

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for headless web servers
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.utils import timezone
from django.db.models import Sum, Count, Avg
from django.views.decorators.csrf import csrf_exempt

from rest_framework.decorators import api_view
from rest_framework.response import Response

from netinsight.analytics.engine import AnalyticsEngine
from netinsight.analytics.topology import generate_topology_pyvis
from netinsight.analytics.telemetry_handler import handle_telemetry_ingestion
from netinsight.classification.classifier import TrafficClassifier
from netinsight.config import settings
from netinsight.optimization.solver import BandwidthOptimizer
from netinsight.prediction.hmm import HiddenMarkovModel
from netinsight.prediction.mdp import MDPRecommendationEngine
from netinsight.prediction.dse import DecisionSupportEngine
from netinsight.dashboard.models import Agent, PacketRecord, FlowRecord, MetricRecord, StateHistory, ThreatHistory, SystemSettings

logger = logging.getLogger(__name__)

# Singleton solvers and classifiers instances
analytics_engine = AnalyticsEngine()
optimizer = BandwidthOptimizer()
hmm_predictor = HiddenMarkovModel()
mdp_engine = MDPRecommendationEngine()
classifier = TrafficClassifier()
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

def ensure_monitor_started():
    """No-op on central server. Packet sniffers run exclusively on client agents."""
    pass

# =====================================================================
# REST APIs for Agents Ingestion
# =====================================================================

@api_view(["POST"])
def api_register_agent(request):
    """API endpoint allowing new client endpoints to discover and register on Laptop 1."""
    try:
        data = request.data
        mac_address = data.get("mac_address", "").lower().strip()
        hostname = data.get("hostname", "Unknown Host")
        device_type = data.get("device_type", "Client Node")
        vendor = data.get("vendor", "Unknown Vendor")
        ip_address = request.META.get("REMOTE_ADDR", "127.0.0.1")

        if not mac_address:
            return Response({"error": "MAC Address is required for registration"}, status=400)

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

        return Response({"status": "success"}, status=200)

    except Exception as e:
        logger.error(f"Error processing telemetry upload: {e}", exc_info=True)
        return Response({"error": f"Internal server error: {e}"}, status=500)

# =====================================================================
# Dashboard HTML Template Views
# =====================================================================

def index_view(request):
    """Renders the main Live Monitor and System Dashboard page."""
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

    # Get latest calculated network-wide metrics
    latest = analytics_engine.get_latest_metrics()
    latest["throughput_mbps"] = latest["throughput"] / 1e6
    latest["latency_ms"] = latest["latency"] * 1000.0

    # Retrieve current network state
    state_record = StateHistory.objects.all().order_by("-timestamp").first()
    state_name = state_record.network_state if state_record else "Normal"

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
        "settings": settings_obj
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

def api_topology_graph(request):
    """Serves the interactive PyVis graph HTML directly for iframe inclusion."""
    html_graph = generate_topology_pyvis()
    return HttpResponse(html_graph, content_type="text/html")

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
    capacity = settings.LINK_CAPACITY

    # Handle manual updates via UI Form POST
    if request.method == "POST":
        try:
            priorities = [float(x) for x in request.POST.getlist("priorities")]
            min_bounds = [float(x) * 1e6 for x in request.POST.getlist("min_bounds")]
            max_bounds = [float(x) * 1e6 for x in request.POST.getlist("max_bounds")]
            capacity = float(request.POST.get("capacity")) * 1e6
            
            # Save priorities dynamically
            settings_obj.lp_priorities = priorities
            settings_obj.save()
        except Exception as e:
            logger.error(f"Error loading manual custom LP settings: {e}")

    classes = ["Web Browsing", "Streaming", "File Transfer", "Critical Services"]

    # Solve LP
    result = optimizer.solve_allocation(priorities, min_bounds, max_bounds, capacity)

    # Map allocations back for template rendering
    allocation_mbps = [x / 1e6 for x in result["allocations"]]
    mapped_allocations = []
    for idx, name in enumerate(classes):
        mapped_allocations.append({
            "class": name,
            "priority": priorities[idx],
            "min_req": min_bounds[idx] / 1e6,
            "max_lim": max_bounds[idx] / 1e6,
            "allocated": allocation_mbps[idx]
        })

    context = {
        "status": result["status"],
        "utility": result["utility"] / 1e6,
        "mapped_allocations": mapped_allocations,
        "kkt": result["kkt_results"],
        "total_capacity_mbps": capacity / 1e6,
        "input_priorities": priorities,
        "input_min_bounds": [x / 1e6 for x in min_bounds],
        "input_max_bounds": [x / 1e6 for x in max_bounds]
    }
    return render(request, "dashboard/optimization.html", context)

def prediction_view(request):
    """Renders HMM transitions matrix and MDP value recommendations."""
    # Query latest state history
    state_record = StateHistory.objects.all().order_by("-timestamp").first()
    curr_state = state_record.network_state if state_record else "Normal"

    # Solve HMM Forecasts
    hmm_1step = hmm_predictor.predict_state_forecast(curr_state, steps=1)
    hmm_3step = hmm_predictor.predict_state_forecast(curr_state, steps=3)

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
        "mdp": mdp_rec,
        "gamma": settings.MDP_DISCOUNT_FACTOR
    }
    return render(request, "dashboard/prediction.html", context)

def classification_view(request):
    """Renders SVM Classifier threat audit tables and live packet predictions."""
    packets_qs = PacketRecord.objects.all().order_by("-timestamp")[:50]
    
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

    context = {
        "model_loaded": classifier.clf is not None,
        "stats": stats,
        "recent_packets": packets_list
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
            logger.info("Successfully updated SystemSettings thresholds dynamically.")
            return redirect("dashboard:index")
        except Exception as e:
            logger.error(f"Failed to save dynamic thresholds: {e}")

    context = {
        "settings": settings_obj
    }
    return render(request, "dashboard/settings.html", context)

# =====================================================================
# Reports & Plots
# =====================================================================

def _plot_to_base64(fig) -> str:
    """Helper converting Matplotlib figure object to base64 PNG string."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=180, bbox_inches="tight", facecolor="#0d111c")
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded

def _generate_throughput_latency_plot(df_metrics: pd.DataFrame) -> str:
    """Generates a dual-axis throughput/latency time-series plot."""
    df = df_metrics.copy()
    df["time_formatted"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%H:%M:%S")
    df["throughput_mbps"] = df["throughput"] / 1e6
    df["latency_ms"] = df["latency"] * 1000.0

    fig, ax1 = plt.subplots(figsize=(10, 5), facecolor="#0d111c")
    ax1.set_facecolor("#0d111c")
    ax2 = ax1.twinx()

    sns.lineplot(
        data=df, x="time_formatted", y="throughput_mbps",
        ax=ax1, color="#3b82f6", label="Throughput (Mbps)",
        linewidth=2.5, errorbar=None
    )
    sns.lineplot(
        data=df, x="time_formatted", y="latency_ms",
        ax=ax2, color="#ef4444", label="Latency (ms)",
        linewidth=2.0, linestyle="--", errorbar=None
    )

    ax1.set_xlabel("Time Stamp", fontsize=10, fontweight="bold", color="#94a3b8")
    ax1.set_ylabel("Throughput (Mbps)", color="#3b82f6", fontsize=10, fontweight="bold")
    ax2.set_ylabel("Latency (ms)", color="#ef4444", fontsize=10, fontweight="bold")

    ax1.tick_params(axis="x", colors="#94a3b8", rotation=45)
    ax1.tick_params(axis="y", colors="#3b82f6")
    ax2.tick_params(axis="y", colors="#ef4444")
    ax1.grid(color="#ffffff", alpha=0.05)
    ax2.grid(False)

    n_points = len(df)
    n_ticks = min(10, n_points)
    if n_points > 0:
        tick_positions = np.linspace(0, n_points - 1, n_ticks, dtype=int)
        ax1.set_xticks(tick_positions)
        ax1.set_xticklabels([df["time_formatted"].iloc[i] for i in tick_positions], rotation=45)

    fig.suptitle("Network Throughput & Latency Correlation", fontsize=12, fontweight="bold", color="#f1f5f9")
    fig.tight_layout()
    return _plot_to_base64(fig)

def _generate_states_distribution_plot(df_states: pd.DataFrame) -> str:
    """Generates a count plot of operational states."""
    colors = {
        "Normal": "#10b981",
        "Busy": "#3b82f6",
        "Congested": "#f59e0b",
        "Under Attack": "#ef4444",
        "Recovering": "#a855f7"
    }
    order = ["Normal", "Busy", "Congested", "Under Attack", "Recovering"]

    fig, ax = plt.subplots(figsize=(6, 5), facecolor="#0d111c")
    ax.set_facecolor("#0d111c")

    sns.countplot(
        data=df_states, x="network_state", order=order, hue="network_state",
        palette=colors, legend=False, ax=ax
    )
    ax.set_xlabel("Operational Network States", fontsize=10, fontweight="bold", color="#94a3b8")
    ax.set_ylabel("Occurrences count", fontsize=10, fontweight="bold", color="#94a3b8")
    ax.tick_params(colors="#94a3b8")
    ax.set_title("Distribution of Operational States", fontsize=11, fontweight="bold", color="#f1f5f9")
    ax.grid(color="#ffffff", alpha=0.05, axis="y")
    fig.tight_layout()

    return _plot_to_base64(fig)

def reports_view(request):
    """Visualizes Matplotlib reports charts in the dashboard panel."""
    plots = {}
    df_metrics = analytics_engine.get_historical_metrics(limit=200)

    if not df_metrics.empty:
        try:
            plots["throughput_latency"] = _generate_throughput_latency_plot(df_metrics)
        except Exception as e:
            logger.error(f"Error generating reports time plot: {e}", exc_info=True)

        states_qs = StateHistory.objects.all().order_by("-timestamp")[:200]
        data = [{"network_state": r.network_state} for r in states_qs]
        df_states = pd.DataFrame(data)

        if not df_states.empty:
            try:
                plots["states_distribution"] = _generate_states_distribution_plot(df_states)
            except Exception as e:
                logger.error(f"Error generating reports state counts plot: {e}", exc_info=True)

    context = {
        "plots": plots,
        "data_available": bool(plots),
    }
    return render(request, "dashboard/reports.html", context)

# =====================================================================
# PDF, CSV, and JSON Document Exports
# =====================================================================

def reports_pdf_download(request):
    """Generates and downloads a formatted PDF network health report using ReportLab."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib import colors

        response = HttpResponse(content_type="application/pdf")
        response["Content-Disposition"] = 'attachment; filename="netinsight_health_report.pdf"'

        doc = SimpleDocTemplate(response, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
        story = []
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1e3a8a"),
            spaceAfter=15
        )
        body_style = ParagraphStyle(
            "ReportBody",
            parent=styles["BodyText"],
            fontSize=10,
            spaceAfter=8
        )

        # Header Title
        story.append(Paragraph("NetInsight-X Health & Security Audit Report", title_style))
        story.append(Paragraph(f"Generated on: {timezone.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", body_style))
        story.append(Spacer(1, 15))

        # 1. Telemetry Agents Section
        story.append(Paragraph("<b>1. Registered Devices Summary</b>", styles["Heading2"]))
        agents = Agent.objects.all()
        agent_data = [["Hostname", "IP Address", "MAC Address", "CPU", "RAM", "Last Seen"]]
        for a in agents:
            agent_data.append([
                a.hostname,
                a.ip_address,
                a.mac_address,
                f"{a.cpu_usage}%",
                f"{a.memory_usage}%",
                a.last_seen.strftime("%H:%M:%S")
            ])
        t_agents = Table(agent_data, colWidths=[100, 90, 110, 50, 50, 80])
        t_agents.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#1e293b")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        story.append(t_agents)
        story.append(Spacer(1, 20))

        # 2. Historical Metrics Section
        story.append(Paragraph("<b>2. Recent Historical Telemetry Metrics</b>", styles["Heading2"]))
        metrics = MetricRecord.objects.all().order_by("-timestamp")[:8]
        metrics_data = [["Timestamp", "Throughput", "Packet Rate", "Utilization", "Latency"]]
        for m in metrics:
            metrics_data.append([
                pd.to_datetime(m.timestamp, unit="s").strftime("%H:%M:%S"),
                f"{m.throughput/1e6:.2f} Mbps",
                f"{m.packet_rate:.1f} pps",
                f"{m.bandwidth_util:.1f}%",
                f"{m.latency * 1000.0:.1f} ms"
            ])
        t_metrics = Table(metrics_data, colWidths=[120, 100, 100, 80, 80])
        t_metrics.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#1e293b")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        story.append(t_metrics)
        story.append(Spacer(1, 20))

        # 3. Threat History Audit
        story.append(Paragraph("<b>3. Security Incidents Logs (SVM Threat Classification)</b>", styles["Heading2"]))
        threats = ThreatHistory.objects.all().order_by("-timestamp")[:10]
        threat_data = [["Timestamp", "Source Host", "Threat Classified", "Severity Level"]]
        for t in threats:
            threat_data.append([
                t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                t.agent.hostname,
                t.threat_type,
                t.severity
            ])
        if len(threat_data) == 1:
            threat_data.append(["No threat records logged.", "-", "-", "-"])
        t_threats = Table(threat_data, colWidths=[130, 110, 130, 110])
        t_threats.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fee2e2")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor("#991b1b")),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#fca5a5")),
            ('FONTSIZE', (0,0), (-1,-1), 9),
        ]))
        story.append(t_threats)

        doc.build(story)
        return response

    except Exception as e:
        logger.error(f"Error compiling PDF report: {e}", exc_info=True)
        return HttpResponse(f"Error generating PDF: {e}", status=500)

def reports_csv_download(request):
    """Exports historical metrics and system operational states to CSV logs."""
    try:
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="netinsight_metrics_history.csv"'

        writer = csv.writer(response)
        # Headers
        writer.writerow(["Timestamp_Unix", "Timestamp_Readable", "Throughput_bps", "Packet_Rate_pps", "Bandwidth_Utilization_pct", "Latency_s", "Packet_Loss_pct"])

        records = MetricRecord.objects.all().order_by("-timestamp")[:500]
        for r in records:
            readable = pd.to_datetime(r.timestamp, unit="s").strftime("%Y-%m-%d %H:%M:%S")
            writer.writerow([
                r.timestamp,
                readable,
                r.throughput,
                r.packet_rate,
                r.bandwidth_util,
                r.latency,
                r.packet_loss
            ])

        return response
    except Exception as e:
        logger.error(f"Error compiling CSV report: {e}", exc_info=True)
        return HttpResponse(f"Error generating CSV: {e}", status=500)

def reports_json_download(request):
    """Exports structured audit logs to a JSON schema for external analysis."""
    try:
        data = {
            "report_timestamp": timezone.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "agents": [],
            "metrics": [],
            "threats": []
        }

        # Query all agents
        for a in Agent.objects.all():
            data["agents"].append({
                "id": str(a.id),
                "mac_address": a.mac_address,
                "hostname": a.hostname,
                "ip_address": a.ip_address,
                "cpu_usage": a.cpu_usage,
                "memory_usage": a.memory_usage,
                "disk_usage": a.disk_usage,
                "active_connections": a.active_connections
            })

        # Query recent metrics
        for m in MetricRecord.objects.all().order_by("-timestamp")[:100]:
            data["metrics"].append({
                "timestamp": m.timestamp,
                "throughput": m.throughput,
                "packet_rate": m.packet_rate,
                "bandwidth_util": m.bandwidth_util,
                "latency": m.latency,
                "packet_loss": m.packet_loss
            })

        # Query threat records
        for t in ThreatHistory.objects.all().order_by("-timestamp")[:200]:
            data["threats"].append({
                "timestamp": t.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "agent_mac": t.agent.mac_address,
                "threat_type": t.threat_type,
                "severity": t.severity
            })

        response = HttpResponse(json.dumps(_to_native_types(data), indent=2), content_type="application/json")
        response["Content-Disposition"] = 'attachment; filename="netinsight_audit_log.json"'
        return response

    except Exception as e:
        logger.error(f"Error compiling JSON report: {e}", exc_info=True)
        return JsonResponse({"error": str(e)}, status=500)

# =====================================================================
# Poll APIs for Dashboard Dynamic Chart.js Updates
# =====================================================================

def api_live_metrics(request):
    """API endpoint returning active metrics, active agents online count, and DSE alerts."""
    try:
        latest = analytics_engine.get_latest_metrics()
        
        # Determine network state dynamically
        state_record = StateHistory.objects.all().order_by("-timestamp").first()
        state_name = state_record.network_state if state_record else "Normal"
        latest["network_state"] = state_name

        # Calculate online count
        from datetime import timedelta
        now = timezone.now()
        active_cutoff = now - timedelta(seconds=15)
        latest["active_devices_count"] = Agent.objects.filter(last_seen__gte=active_cutoff).count()

        # Generate MDP recommendations
        latest["mdp_recommendation"] = mdp_engine.get_recommendation(state_name)

        # Generate DSE advisory alerts
        latest["dse_alerts"] = dse_engine.evaluate_decisions()

        return JsonResponse(_to_native_types(latest))
    except Exception as e:
        logger.error(f"API live metrics error: {e}", exc_info=True)
        return JsonResponse({"error": "Unable to fetch live metrics"}, status=500)

def api_live_packets(request):
    """API endpoint returning latest 20 packet records as JSON."""
    try:
        packets_qs = PacketRecord.objects.all().order_by("-id")[:20]
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
                "agent_hostname": r.agent.hostname
            }
            for r in packets_qs
        ]
        return JsonResponse({"packets": _to_native_types(records)})
    except Exception as e:
        logger.error(f"API packets error: {e}", exc_info=True)
        return JsonResponse({"packets": [], "error": str(e)}, status=500)
