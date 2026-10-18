"""Autonomous Decision Support Engine (DSE) for NetInsight-X.

Evaluates live network telemetry, threat classifications, and link capacity status
to generate actionable advisory alerts for autonomous bandwidth optimization and security response.
"""
import logging

from netinsight.config.singletons import get_analytics_engine, get_traffic_classifier
from netinsight.dashboard.models import SystemSettings

logger = logging.getLogger(__name__)


class DecisionSupportEngine:
    """Evaluates telemetry metrics and threat classifications to output advisory recommendations."""

    def evaluate_decisions(self) -> list[dict]:
        """Evaluates active metrics and threat classifications, returning actionable alert dicts."""
        alerts = []
        try:
            analytics = get_analytics_engine()
            latest = analytics.get_latest_metrics()

            latency = latest.get("latency", 0.0)
            packet_loss = latest.get("packet_loss", 0.0)
            bandwidth_util = latest.get("bandwidth_util", 0.0)
            settings_obj = SystemSettings.objects.first()
            bandwidth_warning = max(0.0, min(1.0, float(settings_obj.bandwidth_threshold))) if settings_obj else 0.75
            loss_warning = max(0.0, min(1.0, float(settings_obj.loss_threshold))) if settings_obj else 0.05
            latency_warning = max(0.0, float(settings_obj.latency_threshold)) if settings_obj else 0.15
            bandwidth_warning_pct = bandwidth_warning * 100.0
            bandwidth_critical_pct = min(100.0, max(85.0, bandwidth_warning_pct + 10.0))

            classifier = get_traffic_classifier()
            last_reasoning = getattr(classifier, "last_llm_reasoning", "")
            last_provider = getattr(classifier, "last_llm_provider", "")

            # 1. Congestion & High Bandwidth Utilization Alert
            if bandwidth_util >= bandwidth_critical_pct:
                alerts.append({
                    "id": "alert-congestion-high",
                    "severity": "Critical",
                    "module": "Bandwidth Optimizer",
                    "title": "Severe Network Link Congestion",
                    "message": f"Bandwidth utilization reached {bandwidth_util:.1f}%. Network link is severely congested.",
                    "action": "Prioritize Critical Services & Cap File Transfer Bandwidth",
                    "description": f"Bandwidth utilization reached {bandwidth_util:.1f}%. Recommend reducing non-essential traffic.",
                    "recommendation": "Prioritize Critical Services & Cap File Transfer Bandwidth",
                    "timestamp": latest.get("timestamp", 0)
                })
            elif bandwidth_util >= bandwidth_warning_pct:
                alerts.append({
                    "id": "alert-congestion-warn",
                    "severity": "Warning",
                    "module": "Bandwidth Optimizer",
                    "title": "High Link Utilization",
                    "message": f"Bandwidth utilization is elevated ({bandwidth_util:.1f}%). Monitor traffic patterns.",
                    "action": "Monitor Streaming and Bulk Data Allocations",
                    "description": f"Bandwidth utilization is elevated ({bandwidth_util:.1f}%). Consider reviewing active data transfers.",
                    "recommendation": "Monitor Streaming and Bulk Data Allocations",
                    "timestamp": latest.get("timestamp", 0)
                })

            # 2. High Latency Alert
            if latency >= latency_warning:
                alerts.append({
                    "id": "alert-latency-high",
                    "severity": "Warning",
                    "module": "QoS Performance",
                    "title": "Elevated Round-Trip Latency",
                    "message": f"Measured RTT latency is {(latency * 1000):.0f} ms.",
                    "action": "Verify edge agent Wi-Fi signal and local link quality",
                    "description": f"Measured RTT latency is {(latency * 1000):.0f} ms.",
                    "recommendation": "Verify edge agent Wi-Fi signal and local link quality",
                    "timestamp": latest.get("timestamp", 0)
                })

            # 3. Packet Loss Alert
            loss_warning_pct = loss_warning * 100.0
            if packet_loss >= loss_warning_pct:
                alerts.append({
                    "id": "alert-loss-high",
                    "severity": "Warning" if packet_loss < max(20.0, loss_warning_pct * 4.0) else "Critical",
                    "module": "QoS Performance",
                    "title": "High TCP Retransmission Estimate",
                    "message": f"Estimated TCP retransmission rate is currently {packet_loss:.1f}%.",
                    "action": "Throttle non-critical streaming to prevent queue drop cascades",
                    "description": f"Estimated TCP retransmission rate is currently {packet_loss:.1f}%.",
                    "recommendation": "Throttle non-critical streaming to prevent queue drop cascades",
                    "timestamp": latest.get("timestamp", 0)
                })

            # 4. DeepSeek AI Threat Alert (only if reasoning was set recently — expires after 30s)
            last_reasoning_ts = getattr(classifier, "last_llm_reasoning_ts", 0)
            reasoning_age = latest.get("timestamp", 0) - last_reasoning_ts
            if (last_provider == "NVIDIA DeepSeek AI" and last_reasoning
                    and "Normal" not in last_reasoning and "Heuristic" not in last_reasoning
                    and reasoning_age < 30):
                alerts.append({
                    "id": "alert-ai-threat",
                    "severity": "Critical",
                    "module": "DeepSeek AI",
                    "title": "DeepSeek AI Threat Incident",
                    "message": last_reasoning,
                    "action": "Enforce strict local QoS rate limits on suspicious ports",
                    "description": last_reasoning,
                    "recommendation": "Enforce strict local QoS rate limits on suspicious ports",
                    "timestamp": latest.get("timestamp", 0)
                })

        except Exception as e:
            logger.error(f"Error evaluating DSE decisions: {e}", exc_info=True)

        return alerts
