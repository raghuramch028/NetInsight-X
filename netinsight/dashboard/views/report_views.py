import base64
import csv
import hmac
import io
import json
import logging
import threading
from typing import Any

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone

from netinsight.analytics.engine import AnalyticsEngine
from netinsight.classification.classifier import get_shared_classifier
from netinsight.config import settings
from netinsight.dashboard.models import (
    Agent,
    MetricRecord,
    PacketRecord,
    StateHistory,
    ThreatHistory,
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
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

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
        story.append(Paragraph("<b>3. Security Incidents Logs (XGBoost Threat Classification)</b>", styles["Heading2"]))
        threats = ThreatHistory.objects.select_related("agent").order_by("-timestamp")[:10]
        threat_data = [["Timestamp", "Source Host", "Threat Classified", "Severity Level"]]
        for t in threats:
            threat_data.append([
                t.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                t.agent.hostname if t.agent else "Unknown",
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

        # Query recent agents
        for a in Agent.objects.all()[:200]:
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
        for t in ThreatHistory.objects.select_related("agent").order_by("-timestamp")[:200]:
            data["threats"].append({
                "timestamp": t.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "agent_mac": t.agent.mac_address if t.agent else "Unknown",
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

def _plot_to_base64(fig) -> str:
    """Helper converting Matplotlib figure object to base64 PNG string."""
    import gc
    try:
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=180, bbox_inches="tight", facecolor="#0d111c")
        buf.seek(0)
        encoded = base64.b64encode(buf.read()).decode("utf-8")
        return encoded
    finally:
        fig.clear()
        plt.close(fig)
        plt.close('all')
        del fig
        gc.collect()

