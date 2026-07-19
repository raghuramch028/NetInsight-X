import logging
from django.utils import timezone
from netinsight.dashboard.models import MetricRecord, ThreatHistory, StateHistory, Agent, SystemSettings

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
            from datetime import timedelta
            cutoff = timezone.now() - timedelta(seconds=15)
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

            # 2. Evaluate Severity Tiers and formulate rules
            
            # RULE A: HMM 'Under Attack' state evaluation
            if latest_state and latest_state.network_state == "Under Attack":
                target_agent = "a registered device"
                threat_type = "network attack"
                if latest_threat and (timezone.now() - latest_threat.timestamp).total_seconds() < 30:
                    target_agent = latest_threat.agent.hostname
                    threat_type = latest_threat.threat_type

                cards.append({
                    "severity": "Critical",
                    "module": "Security Threat Detection",
                    "title": f"Active Cyber Attack Detected: {threat_type}",
                    "message": f"SVM classifier and HMM state forecast confirm the network is Under Attack. Threat source: {target_agent}.",
                    "action": f"Isolate {target_agent} immediately. Apply LP QoS rules to prioritize critical control systems."
                })

            # RULE B: SVM Security Alerts Check (even if HMM is still transitioning)
            elif latest_threat and (timezone.now() - latest_threat.timestamp).total_seconds() < 30:
                severity = latest_threat.severity
                cards.append({
                    "severity": severity,
                    "module": "Security Threat Detection",
                    "title": f"Suspicious Activity: {latest_threat.threat_type}",
                    "message": f"SVM classified traffic anomalies on host {latest_threat.agent.hostname}.",
                    "action": f"Inspect active connection ports on {latest_threat.agent.hostname}. Restrict non-SSL socket traffic."
                })

            # RULE C: HMM 'Congested' state evaluation
            if latest_state and latest_state.network_state == "Congested":
                cards.append({
                    "severity": "Warning",
                    "module": "Congestion Control",
                    "title": "High Network Congestion Forecasted",
                    "message": "Markovian prediction indicates imminent link saturation. Packet loss rates or queue delays are spiking.",
                    "action": "Apply LP bandwidth throttling for Streaming and File Transfer classes."
                })

            # RULE D: Telemetry Metrics Check (raw threshold alerts)
            if latest_metric:
                # Latency alert
                if latest_metric.latency > settings_obj.latency_threshold:
                    cards.append({
                        "severity": "Warning",
                        "module": "Traffic Analytics",
                        "title": f"Latency Violation: {latest_metric.latency * 1000.0:.1f}ms",
                        "message": f"Average network round-trip time exceeds configured threshold of {settings_obj.latency_threshold * 1000.0:.0f}ms.",
                        "action": "Check for bufferbloat or routing bottlenecks. Verify link speeds."
                    })
                
                # Packet loss alert
                if latest_metric.packet_loss > (settings_obj.loss_threshold * 100.0):
                    cards.append({
                        "severity": "Critical",
                        "module": "Traffic Analytics",
                        "title": f"High Packet Loss: {latest_metric.packet_loss:.2f}%",
                        "message": f"Network transmission error rates exceed warning boundary of {settings_obj.loss_threshold * 100.0:.1f}%.",
                        "action": "Identify duplicate sequences. Investigate potential physical layer issues or Wi-Fi interference."
                    })

            # RULE E: System Health Alerts (e.g. host disk space low)
            for agent in active_agents:
                if agent.disk_usage > 90.0:
                    cards.append({
                        "severity": "Warning",
                        "module": "System Health",
                        "title": f"Disk Space Low: {agent.hostname}",
                        "message": f"Monitored host {agent.hostname} reports disk utilization at {agent.disk_usage}%.",
                        "action": "Free up space on the client machine to prevent telemetry logs writing blockages."
                    })
                if agent.cpu_usage > 90.0:
                    cards.append({
                        "severity": "Warning",
                        "module": "System Health",
                        "title": f"CPU Utilization Spiking: {agent.hostname}",
                        "message": f"Monitored host {agent.hostname} is running at {agent.cpu_usage}% CPU load.",
                        "action": "Inspect active threads using task managers. Close unneeded processes."
                    })

            # RULE F: Normal Status Card
            if not cards:
                cards.append({
                    "severity": "Information",
                    "module": "System Health",
                    "title": "All Systems Normal",
                    "message": "Network utilization and latency bounds are within acceptable limits. No active security alerts.",
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
