import base64
import csv
import io
import json
import logging

import matplotlib

matplotlib.use("Agg")  # Non-interactive backend for headless web servers
import matplotlib.pyplot as plt
import pandas as pd
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone

from netinsight.config.singletons import (
    get_analytics_engine,
    get_dse_engine,
    get_lp_optimizer,
    get_traffic_classifier,
)
from netinsight.dashboard.models import Agent, MetricRecord, ThreatHistory
from netinsight.dashboard.views.utils import (
    require_dashboard_auth as _require_dashboard_auth,
)
from netinsight.dashboard.views.utils import (
    to_native_types as _to_native_types,
)

logger = logging.getLogger(__name__)

analytics_engine = get_analytics_engine()
optimizer = get_lp_optimizer()
classifier = get_traffic_classifier()
dse_engine = get_dse_engine()


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

    context = {
        "plots": plots,
        "data_available": bool(plots),
    }
    return render(request, "dashboard/reports.html", context)


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
                a.last_seen.strftime("%H:%M:%S") if a.last_seen else "N/A"
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
                pd.to_datetime(m.timestamp, unit="s").strftime("%H:%M:%S") if m.timestamp else "N/A",
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
        story.append(Paragraph("<b>3. Security Incidents Logs (DeepSeek AI Classification)</b>", styles["Heading2"]))
        threats = ThreatHistory.objects.select_related("agent").order_by("-timestamp")[:10]
        threat_data = [["Timestamp", "Source Host", "Threat Classified", "Severity Level"]]
        for t in threats:
            threat_data.append([
                t.timestamp.strftime("%Y-%m-%d %H:%M:%S") if t.timestamp else "N/A",
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
        logger.error(f"PDF generation error: {e}", exc_info=True)
        return HttpResponse(f"Error generating PDF report: {e}", status=500)


@_require_dashboard_auth
def reports_csv_download(request):
    """Exports historical metrics records to a downloadable CSV file."""
    try:
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = 'attachment; filename="netinsight_metrics_export.csv"'

        writer = csv.writer(response)
        writer.writerow(["Timestamp", "Throughput_bps", "Packet_Rate_pps", "Bandwidth_Utilization_pct", "Latency_sec", "Packet_Loss_pct"])

        records = MetricRecord.objects.all().order_by("-timestamp")[:1000]
        for r in records:
            writer.writerow([r.timestamp, r.throughput, r.packet_rate, r.bandwidth_util, r.latency, r.packet_loss])

        return response
    except Exception as e:
        logger.error(f"CSV export error: {e}", exc_info=True)
        return HttpResponse(f"Error exporting CSV: {e}", status=500)


@_require_dashboard_auth
def reports_json_download(request):
    """Exports historical metrics and active devices snapshot to a downloadable JSON file."""
    try:
        metrics_qs = MetricRecord.objects.all().order_by("-timestamp")[:500]
        agents_qs = Agent.objects.all()

        export_data = {
            "exported_at": timezone.now().isoformat(),
            "agents": [
                {
                    "mac_address": a.mac_address,
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "device_type": a.device_type,
                    "vendor": a.vendor,
                    "last_seen": a.last_seen.isoformat() if a.last_seen else None
                }
                for a in agents_qs
            ],
            "metrics": [
                {
                    "timestamp": m.timestamp,
                    "throughput": m.throughput,
                    "packet_rate": m.packet_rate,
                    "bandwidth_util": m.bandwidth_util,
                    "latency": m.latency,
                    "packet_loss": m.packet_loss
                }
                for m in metrics_qs
            ]
        }

        response = HttpResponse(json.dumps(_to_native_types(export_data), indent=2), content_type="application/json")
        response["Content-Disposition"] = 'attachment; filename="netinsight_full_export.json"'
        return response
    except Exception as e:
        logger.error(f"JSON export error: {e}", exc_info=True)
        return HttpResponse(f"Error exporting JSON: {e}", status=500)


def _generate_throughput_latency_plot(df: pd.DataFrame) -> str:
    """Generates a Matplotlib throughput vs latency dual-axis time-series plot."""
    df = df.copy()
    df["time_formatted"] = pd.to_datetime(df["timestamp"], unit="s").dt.strftime("%H:%M:%S")
    df["throughput_mbps"] = df["throughput"] / 1e6
    df["latency_ms"] = df["latency"] * 1000.0

    fig, ax1 = plt.subplots(figsize=(10, 5), facecolor="#0d111c")
    ax1.set_facecolor("#0d111c")
    ax2 = ax1.twinx()

    ax1.plot(df["time_formatted"], df["throughput_mbps"], color="#3b82f6", linewidth=2, label="Throughput (Mbps)")
    ax2.plot(df["time_formatted"], df["latency_ms"], color="#ef4444", linewidth=1.5, linestyle="--", label="Latency (ms)")

    ax1.set_xlabel("Timestamp", color="#94a3b8")
    ax1.set_ylabel("Throughput (Mbps)", color="#3b82f6")
    ax2.set_ylabel("Latency (ms)", color="#ef4444")

    ax1.tick_params(axis="x", colors="#94a3b8", rotation=45)
    ax1.tick_params(axis="y", colors="#3b82f6")
    ax2.tick_params(axis="y", colors="#ef4444")

    plt.title("NetInsight-X Historical Telemetry Performance", color="#ffffff", fontsize=12, pad=15)
    fig.tight_layout()

    buf = io.BytesIO()
    plt.savefig(buf, format="png", dpi=120, bbox_inches="tight", facecolor=fig.get_facecolor())
    plt.close(fig)
    return base64.b64encode(buf.getvalue()).decode("utf-8")
