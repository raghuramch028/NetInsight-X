"""Autonomous Decision Support Engine (DSE) for NetInsight-X.

Evaluates live network telemetry, threat classifications, and link capacity status
to generate actionable advisory alerts for autonomous bandwidth optimization and security response.
"""
import logging
import time

from datetime import timedelta

from django.db.models import Sum
from django.utils import timezone

from netinsight.config import settings as app_settings
from netinsight.config.singletons import get_analytics_engine, get_traffic_classifier
from netinsight.dashboard.models import Agent, FlowRecord, SystemSettings

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

            # Escalate repeated classified flows; the agent still requires local opt-in.
            response_cutoff = time.time() - 60.0
            threat_flows = FlowRecord.objects.filter(
                end_time__gte=response_cutoff,
                policy_action="RESTRICT_FLOW",
                classification_engine="XGBoost ML Engine",
                classification_confidence__gte=0.80,
            )
            qualified_agent_ids = list(
                threat_flows.values("agent_id")
                .annotate(packet_count=Sum("packet_count"))
                .filter(packet_count__gte=5)
                .values_list("agent_id", flat=True)
            )
            unqualified_flow_count = threat_flows.exclude(agent_id__in=qualified_agent_ids).count()
            if unqualified_flow_count:
                alerts.append({
                    "id": "alert-flow-monitor",
                    "severity": "Info",
                    "module": "Threat Response",
                    "title": "Suspicious Flow Under Observation",
                    "message": (
                        f"{unqualified_flow_count} suspicious flow(s) are being monitored. "
                        "The policy waits for at least five suspicious packets from this source agent before issuing restrictions."
                    ),
                    "action": "Monitor only until repeated evidence reaches the configured prototype threshold.",
                    "description": "A repeated-evidence threshold helps avoid responding to a single possible false positive.",
                    "recommendation": "Continue observing until there is sufficient repeated evidence.",
                    "timestamp": time.time(),
                })
            flagged_flows = list(
                threat_flows.filter(agent_id__in=qualified_agent_ids)
                .select_related("agent").order_by("-end_time")[:10]
            )
            if flagged_flows:
                recipient_count = Agent.objects.filter(
                    last_seen__gte=timezone.now() - timedelta(seconds=15)
                ).exclude(id__in=qualified_agent_ids).count()
                reclaimed_bps = sum(flow.policy_estimated_reclaimed_bps for flow in flagged_flows)
                reclaimed_mbps = reclaimed_bps / 1e6
                per_device_mbps = reclaimed_mbps / recipient_count if recipient_count else 0.0
                flagged_agents = {flow.agent_id: flow.agent for flow in flagged_flows}
                confirmed_blocks = []
                seen_rule_keys = set()
                for flow in flagged_flows:
                    for rule in flagged_agents[flow.agent_id].active_flow_blocks or []:
                        rule_key = (
                            rule.get("src_ip"),
                            int(rule.get("src_port", 0)),
                            rule.get("dst_ip"),
                            int(rule.get("dst_port", 0)),
                            rule.get("protocol"),
                            rule.get("demo_event_id"),
                        )
                        if (
                            rule.get("src_ip") == flow.first_src_ip
                            and int(rule.get("src_port", 0)) == flow.first_src_port
                            and rule.get("dst_ip") == flow.first_dst_ip
                            and int(rule.get("dst_port", 0)) == flow.first_dst_port
                            and rule.get("protocol") == flow.protocol
                            and rule.get("demo_event_id") == flow.demo_event_id
                            and rule_key not in seen_rule_keys
                        ):
                            confirmed_blocks.append(rule)
                            seen_rule_keys.add(rule_key)
                            break
                confirmed_block_count = len(confirmed_blocks)
                flow_names = ", ".join(
                    f"{flow.threat_label} on {flow.agent.hostname}" for flow in flagged_flows[:3]
                )
                enforcement_mode_enabled = (
                    app_settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT
                    or app_settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT
                    or app_settings.NETINSIGHT_ENABLE_LIVE_FLOW_ENFORCEMENT
                )
                if app_settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT and enforcement_mode_enabled and confirmed_block_count:
                    action = (
                        f"Host firewall confirms {confirmed_block_count} outbound flow block(s). "
                        "Rules are temporary; review for false positives."
                    )
                    message = (
                        f"The firewall reports blocks for {len(flagged_flows)} suspicious flow(s): {flow_names}. "
                        f"Estimated observed rate was {reclaimed_mbps:.2f} Mbps. The freed shared-link capacity "
                        "is available to other devices, but per-device shares are not guaranteed."
                    )
                    title = "Suspicious Outbound Flows Blocked"
                elif app_settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT and enforcement_mode_enabled:
                    action = (
                        "Waiting for an opted-in Windows agent running as Administrator to confirm firewall rules. "
                        "No block is confirmed yet."
                    )
                    message = (
                        f"Restriction rules are available for {len(flagged_flows)} suspicious flow(s): {flow_names}. "
                        f"Estimated observed rate is {reclaimed_mbps:.2f} Mbps."
                    )
                    title = "Threat-Driven Flow Restriction Pending"
                else:
                    action = "Simulation only: enable NETINSIGHT_ENABLE_FLOW_ENFORCEMENT on server and Windows agent to block these flows."
                    message = (
                        f"Would restrict {len(flagged_flows)} repeated threat flow(s): {flow_names}. "
                        f"Estimated flow rate {reclaimed_mbps:.2f} Mbps; it could be shared among "
                        f"{recipient_count} other active device(s) at approximately {per_device_mbps:.2f} Mbps each."
                    )
                    title = "Threat-Driven Bandwidth Redistribution (Simulation)"
                alerts.append({
                    "id": "alert-flow-response",
                    "severity": "Warning",
                    "module": "Threat Response",
                    "title": title,
                    "message": message,
                    "action": action,
                    "description": "Outbound restrictions are applied by the source Windows host firewall; shared-link capacity becomes available, but the application cannot guarantee exact shares without router QoS.",
                    "recommendation": "Review the flagged flow before enabling enforcement.",
                    "timestamp": time.time(),
                })

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
