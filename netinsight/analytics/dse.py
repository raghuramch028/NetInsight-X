"""Autonomous Decision Support Engine (DSE) for NetInsight-X.

Evaluates live network telemetry, threat classifications, and link capacity status
to generate actionable advisory alerts for autonomous bandwidth optimization and security response.
"""
import logging

from netinsight.config import settings
from netinsight.config.singletons import get_analytics_engine, get_traffic_classifier

logger = logging.getLogger(__name__)


class DecisionSupportEngine:
    """Evaluates telemetry metrics and threat classifications to output advisory recommendations."""

    def evaluate_decisions(self) -> list[dict]:
        """Evaluates active metrics and threat classifications, returning actionable alert dicts."""
        alerts = []
        try:
            analytics = get_analytics_engine()
            latest = analytics.get_latest_metrics()

            throughput = latest.get("throughput", 0.0)
            latency = latest.get("latency", 0.0)
            packet_loss = latest.get("packet_loss", 0.0)
            bandwidth_util = latest.get("bandwidth_util", 0.0)

            classifier = get_traffic_classifier()
            last_engine = getattr(classifier, "last_engine_used", "DeepSeek AI")
            last_reasoning = getattr(classifier, "last_llm_reasoning", "")

            # 1. Congestion & High Bandwidth Utilization Alert
            if bandwidth_util >= 85.0:
                alerts.append({
                    "id": "alert-congestion-high",
                    "severity": "Critical",
                    "module": "Bandwidth Optimizer",
                    "title": "Severe Network Link Congestion",
                    "message": f"Bandwidth utilization reached {bandwidth_util:.1f}%. Autonomous LP Bandwidth Optimizer has dynamically adjusted QoS bounds.",
                    "action": "Prioritize Critical Services & Cap File Transfer Bandwidth",
                    "description": f"Bandwidth utilization reached {bandwidth_util:.1f}%. Autonomous LP Bandwidth Optimizer has dynamically adjusted QoS bounds.",
                    "recommendation": "Prioritize Critical Services & Cap File Transfer Bandwidth",
                    "timestamp": latest.get("timestamp", 0)
                })
            elif bandwidth_util >= 60.0:
                alerts.append({
                    "id": "alert-congestion-warn",
                    "severity": "Warning",
                    "module": "Bandwidth Optimizer",
                    "title": "High Link Utilization",
                    "message": f"Bandwidth utilization is elevated ({bandwidth_util:.1f}%). LP Optimizer is actively balancing traffic flow.",
                    "action": "Monitor Streaming and Bulk Data Allocations",
                    "description": f"Bandwidth utilization is elevated ({bandwidth_util:.1f}%). LP Optimizer is actively balancing traffic flow.",
                    "recommendation": "Monitor Streaming and Bulk Data Allocations",
                    "timestamp": latest.get("timestamp", 0)
                })

            # 2. High Latency Alert
            if latency >= 0.15:
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
            if packet_loss >= 5.0:
                alerts.append({
                    "id": "alert-loss-high",
                    "severity": "Warning" if packet_loss < 20.0 else "Critical",
                    "module": "QoS Performance",
                    "title": "High Packet Loss Detected",
                    "message": f"Packet loss rate is currently {packet_loss:.1f}%.",
                    "action": "Throttle non-critical streaming to prevent queue drop cascades",
                    "description": f"Packet loss rate is currently {packet_loss:.1f}%.",
                    "recommendation": "Throttle non-critical streaming to prevent queue drop cascades",
                    "timestamp": latest.get("timestamp", 0)
                })

            # 4. DeepSeek AI Threat Alert (if reasoning is present)
            if last_reasoning and "Normal" not in last_reasoning and "Heuristic" not in last_reasoning:
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
