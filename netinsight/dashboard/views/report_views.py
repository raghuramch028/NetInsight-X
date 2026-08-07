import base64
import csv
import io
import json
import logging

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils import timezone

from netinsight.config.singletons import (
    get_analytics_engine,
    get_dse_engine,
    get_hmm_predictor,
    get_lp_optimizer,
    get_mdp_engine,
    get_traffic_classifier,
)
from netinsight.dashboard.models import (
    Agent,
    MetricRecord,
    StateHistory,
    ThreatHistory,
)
from netinsight.dashboard.views.utils import (
    require_dashboard_auth as _require_dashboard_auth,
)
from netinsight.dashboard.views.utils import (
    to_native_types as _to_native_types,
)
from netinsight.prediction.markov import MarkovPredictor

logger = logging.getLogger(__name__)

# Centralized thread-safe singleton references
analytics_engine = get_analytics_engine()
optimizer = get_lp_optimizer()
hmm_predictor = get_hmm_predictor()
markov_predictor = MarkovPredictor()
mdp_engine = get_mdp_engine()
classifier = get_traffic_classifier()
dse_engine = get_dse_engine()

# =====================================================================
# REST APIs for Agents Ingestion
# =====================================================================

@_require_dashboard_auth
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

@_require_dashboard_auth
def reports_pdf_download(request):
    """Generates and downloads a formatted PDF network health report using ReportLab."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )

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
        story.append(Paragraph("<b>3. Security Incidents Logs (Heuristic/LLM Threat Classification)</b>", styles["Heading2"]))
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

@_require_dashboard_auth
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

@_require_dashboard_auth
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

