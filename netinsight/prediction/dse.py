import logging
import time
from datetime import timedelta

from django.utils import timezone

from netinsight.dashboard.models import (
    Agent,
    MetricRecord,
    StateHistory,
    SystemSettings,
    ThreatHistory,
)

logger = logging.getLogger(__name__)

class DecisionSupportEngine:
    """Aggregates variables from all DSS modules to formulate actionable administrator advice cards."""

    def __init__(self):
        pass

    def evaluate_decisions(self) -> list[dict]:
        """Runs the rule evaluator to compile active advisory alerts.

        Returns:
            list[dict]: Array of alert card structures.
        """
        cards = []

        try:
            # 1. Fetch latest state data
            settings_obj = SystemSettings.objects.first()
            if not settings_obj:
                # Create a default settings object if none exists
                settings_obj = SystemSettings.objects.create()

            latest_metric = MetricRecord.objects.all().order_by("-timestamp").first()
            latest_state = StateHistory.objects.all().order_by("-timestamp").first()
            latest_threat = ThreatHistory.objects.all().order_by("-timestamp").first()

            # Active agents seen in last 15 seconds
            now_dt = timezone.now()
            now_ts = time.time()
            cutoff = now_dt - timedelta(seconds=15)
            active_agents = Agent.objects.filter(last_seen__gte=cutoff)

            # Check empty state
            if not active_agents.exists():
                cards.append({
                    "severity": "Information",
                    "module": "System Health",
                    "title": "No Telemetry Available",
                    "message": "No active telemetry agents have connected to the central server.",
                    "action": "Ensure agent/main.py is executing on monitored devices and points to this server IP."
                })
                return cards

            # Identify primary active target host for specific error reporting
            primary_agent = active_agents.order_by("-active_connections").first()
            agent_desc = f"{primary_agent.hostname} (IP: {primary_agent.ip_address}, MAC: {primary_agent.mac_address})" if primary_agent else "Connected Client"

            # Check if latest_state record is fresh (within last 30s)
            is_fresh_state = latest_state and (now_ts - latest_state.timestamp) < 30.0

            # 2. Evaluate Severity Tiers and formulate rules

            # RULE A: HMM 'Under Attack' state evaluation (Requires FRESH state)
            if is_fresh_state and latest_state.network_state == "Under Attack":
                target_agent_str = agent_desc
                threat_type = "Traffic Surge / Anomaly"

                if latest_threat and (now_dt - latest_threat.timestamp).total_seconds() < 30:
                    if latest_threat.agent:
                        target_agent_str = f"{latest_threat.agent.hostname} (IP: {latest_threat.agent.ip_address})"
                    threat_type = latest_threat.threat_type

                cards.append({
                    "severity": "Critical",
                    "module": "Security Threat Detection",
                    "title": f"Active Security Threat: {threat_type}",
                    "message": f"NVIDIA DeepSeek AI classifier and HMM state forecast detected an active attack on {target_agent_str}.",
                    "action": f"Inspect active connection ports on {primary_agent.hostname} ({primary_agent.ip_address}). Apply LP QoS rules to throttle heavy transfer flows."
                })

            # RULE B: LLM Security Alerts Check (even if HMM is still transitioning)
            elif latest_threat and (now_dt - latest_threat.timestamp).total_seconds() < 30:
                severity = latest_threat.severity
                target_agent_str = f"{latest_threat.agent.hostname} (IP: {latest_threat.agent.ip_address})" if latest_threat.agent else agent_desc
                cards.append({
                    "severity": severity,
                    "module": "Security Threat Detection",
                    "title": f"Suspicious Activity: {latest_threat.threat_type}",
                    "message": f"NVIDIA DeepSeek AI classified traffic anomalies on host {target_agent_str}.",
                    "action": f"Inspect active connection ports on {target_agent_str}. Restrict non-SSL socket traffic."
                })

            # RULE C: HMM 'Congested' state evaluation (Requires FRESH state)
            if is_fresh_state and latest_state.network_state == "Congested":
                cards.append({
                    "severity": "Warning",
                    "module": "Congestion Control",
                    "title": "High Network Congestion Forecasted",
                    "message": f"Markovian prediction indicates link saturation on {primary_agent.hostname}. Packet loss or queue delays are spiking.",
                    "action": "Apply LP bandwidth throttling for Streaming and File Transfer classes."
                })

            # RULE D: Telemetry Metrics Check (raw threshold alerts - Requires FRESH metric)
            if latest_metric and (now_ts - latest_metric.timestamp) < 30.0:
                # Latency alert
                if latest_metric.latency > settings_obj.latency_threshold:
                    cards.append({
                        "severity": "Warning",
                        "module": "Traffic Analytics",
                        "title": f"Latency Violation: {latest_metric.latency * 1000.0:.1f}ms",
                        "message": f"Average network round-trip time on {primary_agent.hostname} exceeds threshold of {settings_obj.latency_threshold * 1000.0:.0f}ms.",
                        "action": "Check for bufferbloat or routing bottlenecks. Verify link speeds."
                    })

                # Packet loss alert
                if latest_metric.packet_loss > (settings_obj.loss_threshold * 100.0):
                    cards.append({
                        "severity": "Critical",
                        "module": "Traffic Analytics",
                        "title": f"High Packet Loss: {latest_metric.packet_loss:.2f}%",
                        "message": f"Transmission error rates on {primary_agent.hostname} exceed boundary of {settings_obj.loss_threshold * 100.0:.1f}%.",
                        "action": "Identify duplicate sequences. Investigate potential physical layer issues or Wi-Fi interference."
                    })

            # RULE E: System Health Alerts (e.g. host disk space low)
            for agent in active_agents:
                if agent.disk_usage > 90.0:
                    cards.append({
                        "severity": "Warning",
                        "module": "System Health",
                        "title": f"Disk Space Low: {agent.hostname}",
                        "message": f"Monitored host {agent.hostname} (IP: {agent.ip_address}) reports disk utilization at {agent.disk_usage}%.",
                        "action": "Free up space on the client machine to prevent telemetry logs writing blockages."
                    })
                if agent.cpu_usage > 90.0:
                    cards.append({
                        "severity": "Warning",
                        "module": "System Health",
                        "title": f"CPU Utilization Spiking: {agent.hostname}",
                        "message": f"Monitored host {agent.hostname} (IP: {agent.ip_address}) is running at {agent.cpu_usage}% CPU load.",
                        "action": "Inspect active threads using task managers. Close unneeded processes."
                    })

            # RULE F: Normal Status Card
            if not cards:
                cards.append({
                    "severity": "Information",
                    "module": "System Health",
                    "title": "All Systems Normal",
                    "message": f"Network utilization and latency bounds for {agent_desc} are within acceptable limits. No active security alerts.",
                    "action": "Monitor telemetry live. LP bandwidth allocation is running under optimal balance configurations."
                })

        except Exception as e:
            logger.error(f"Error in Decision Support Engine: {e}", exc_info=True)
            cards.append({
                "severity": "Warning",
                "module": "DSE Engine",
                "title": "DSE Evaluation Failed",
                "message": f"An error occurred while evaluating advisory rules: {e}",
                "action": "Contact administrator. Check database migrations integrity."
            })

        return cards
