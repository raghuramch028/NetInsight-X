import time
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from agent.flow_firewall import WindowsFlowFirewall
from netinsight.analytics.dse import DecisionSupportEngine
from netinsight.analytics.telemetry_handler import (
    _execute_async_telemetry_worker,
    handle_telemetry_ingestion,
)
from netinsight.dashboard.models import Agent, FlowRecord, MetricRecord, PacketRecord, SystemSettings
from netinsight.dashboard.views.api_views import _get_flow_restrictions, _validated_demo_event


class DashboardMetricTests(TestCase):
    def _agent(self, suffix, **kwargs):
        return Agent.objects.create(
            mac_address=f"02:00:00:00:00:{suffix:02x}",
            hostname=f"agent-{suffix}",
            ip_address=f"192.0.2.{suffix}",
            device_type="Test",
            vendor="Test",
            **kwargs,
        )

    def test_throughput_metric_sums_active_agent_rates(self):
        first_agent = self._agent(1, current_throughput=1_250_000.0)
        self._agent(2, current_throughput=750_000.0)

        _execute_async_telemetry_worker(first_agent.id, {}, [])

        metric = MetricRecord.objects.latest("timestamp")
        self.assertEqual(metric.throughput, 2_000_000.0)

    def test_agent_throughput_uses_counter_delta(self):
        agent = self._agent(
            4,
            bytes_sent=1000,
            bytes_recv=1000,
            throughput_sampled_at=timezone.now() - timedelta(seconds=2),
        )
        stats = {"bytes_sent": 2000, "bytes_recv": 4000}

        with patch("netinsight.analytics.telemetry_handler._telemetry_inflight_semaphore.acquire", return_value=False):
            handle_telemetry_ingestion(agent, stats, [])

        agent.refresh_from_db()
        self.assertGreater(agent.current_throughput, 12_000.0)
        self.assertLess(agent.current_throughput, 20_000.0)

    def test_classification_page_uses_persisted_packet_label(self):
        agent = self._agent(3)
        PacketRecord.objects.create(
            agent=agent,
            src_ip="192.0.2.3",
            dst_ip="198.51.100.10",
            src_port=12345,
            dst_port=443,
            protocol="TCP",
            size=1200,
            ttl=64,
            timestamp=time.time(),
            threat_label="DoS / DDoS",
        )

        with patch("netinsight.dashboard.views.page_views.classifier.classify_packet", side_effect=AssertionError):
            response = self.client.get("/classification/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "DoS / DDoS")


class DecisionSupportThresholdTests(TestCase):
    def setUp(self):
        self.settings = SystemSettings.objects.create(
            bandwidth_threshold=0.9,
            loss_threshold=0.2,
            latency_threshold=0.3,
        )
        self.latest = {
            "timestamp": time.time(),
            "bandwidth_util": 80.0,
            "packet_loss": 10.0,
            "latency": 0.2,
        }
        self.classifier = SimpleNamespace(
            last_llm_reasoning="",
            last_llm_reasoning_ts=0.0,
            last_llm_provider="XGBoost (CICIoT2023)",
        )

    def _evaluate(self):
        analytics = SimpleNamespace(get_latest_metrics=lambda: self.latest)
        with (
            patch("netinsight.analytics.dse.get_analytics_engine", return_value=analytics),
            patch("netinsight.analytics.dse.get_traffic_classifier", return_value=self.classifier),
        ):
            return DecisionSupportEngine().evaluate_decisions()

    def test_saved_thresholds_control_performance_alerts(self):
        self.assertEqual(self._evaluate(), [])

        self.settings.bandwidth_threshold = 0.7
        self.settings.loss_threshold = 0.05
        self.settings.latency_threshold = 0.15
        self.settings.save()

        alert_ids = {alert["id"] for alert in self._evaluate()}
        self.assertEqual(
            alert_ids,
            {"alert-congestion-warn", "alert-loss-high", "alert-latency-high"},
        )

    def test_ai_threat_alert_requires_recent_llm_result(self):
        self.classifier.last_llm_reasoning = "DoS threat detected"
        self.classifier.last_llm_reasoning_ts = time.time()
        self.assertNotIn("alert-ai-threat", {alert["id"] for alert in self._evaluate()})

        self.classifier.last_llm_provider = "NVIDIA DeepSeek AI"
        self.assertIn("alert-ai-threat", {alert["id"] for alert in self._evaluate()})

    def test_repeated_flagged_flows_propose_redistribution(self):
        threat_agent = Agent.objects.create(
            mac_address="02:00:00:00:01:01",
            hostname="repeated-threat",
            ip_address="192.0.2.11",
            device_type="Demo",
            vendor="Demo",
            active_flow_blocks=[{
                "src_ip": "192.0.2.11",
                "src_port": 5000,
                "dst_ip": "192.168.1.50",
                "dst_port": 45678,
                "protocol": "UDP",
                "demo_event_id": "demo-threat-event",
            }],
        )
        recipient = Agent.objects.create(
            mac_address="02:00:00:00:01:02",
            hostname="normal-device",
            ip_address="192.0.2.22",
            device_type="Demo",
            vendor="Demo",
            current_throughput=2_000_000.0,
        )
        now = time.time()
        for port in range(5):
            FlowRecord.objects.create(
                agent=threat_agent,
                flow_key=f"flow-{port}",
                start_time=now - 2.0,
                end_time=now,
                duration=1.0,
                packet_count=1,
                byte_count=250_000,
                avg_packet_size=250_000.0,
                protocol="UDP",
                threat_label="Reconnaissance",
                classification_engine="XGBoost ML Engine",
                classification_confidence=0.93,
                first_src_ip="192.0.2.11",
                first_src_port=5000,
                first_dst_ip="192.168.1.50",
                first_dst_port=45678,
                policy_action="RESTRICT_FLOW",
                policy_estimated_reclaimed_bps=2_000_000.0,
                demo_event_id="demo-threat-event",
            )

        with (
            patch("netinsight.analytics.dse.app_settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True),
            patch("netinsight.analytics.dse.app_settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT", True),
        ):
            response_alert = next(
                alert for alert in self._evaluate() if alert["id"] == "alert-flow-response"
            )
        self.assertEqual(response_alert["title"], "Suspicious Outbound Flows Blocked")
        self.assertIn("Host firewall confirms 1 outbound flow block(s)", response_alert["action"])
        recipient.refresh_from_db()
        self.assertEqual(recipient.current_throughput, 2_000_000.0)

    def test_under_threshold_flows_remain_monitor_only(self):
        agent = Agent.objects.create(
            mac_address="02:00:00:00:02:01",
            hostname="early-scan",
            ip_address="192.0.2.31",
            device_type="Demo",
            vendor="Demo",
        )
        now = time.time()
        for port in range(4):
            FlowRecord.objects.create(
                agent=agent,
                flow_key=f"early-scan-{port}",
                start_time=now - 1.0,
                end_time=now,
                duration=1.0,
                packet_count=1,
                byte_count=1000,
                avg_packet_size=1000.0,
                protocol="TCP",
                threat_label="Reconnaissance",
                classification_engine="XGBoost ML Engine",
                classification_confidence=0.93,
                first_src_ip="192.0.2.31",
                first_src_port=4000 + port,
                first_dst_ip="192.168.1.50",
                first_dst_port=45678,
                policy_action="RESTRICT_FLOW",
                policy_estimated_reclaimed_bps=8000.0,
                demo_event_id="under-threshold-event",
            )

        alert_ids = {alert["id"] for alert in self._evaluate()}
        self.assertNotIn("alert-flow-response", alert_ids)
        self.assertIn("alert-flow-monitor", alert_ids)


class FlowEnforcementTests(TestCase):
    def _agent(self, suffix=1):
        return Agent.objects.create(
            mac_address=f"02:00:00:00:03:{suffix:02x}",
            hostname="demo-host",
            ip_address=f"192.0.2.{40 + suffix}",
            device_type="Windows",
            vendor="Test",
        )

    def _flow(self, agent, suffix, **kwargs):
        now = time.time()
        defaults = {
            "agent": agent,
            "flow_key": f"demo-{suffix}",
            "start_time": now - 4,
            "end_time": now,
            "duration": 3.5,
            "packet_count": 8,
            "byte_count": 512,
            "avg_packet_size": 64,
            "protocol": "UDP",
            "threat_label": "DoS / DDoS",
            "classification_engine": "XGBoost ML Engine",
            "classification_confidence": 0.998,
            "first_src_ip": str(agent.ip_address),
            "first_src_port": 51234,
            "first_dst_ip": "192.168.1.50",
            "first_dst_port": 45678,
            "policy_action": "RESTRICT_FLOW",
            "policy_estimated_reclaimed_bps": 1200.0,
            "demo_event_id": "c3a0d6e1-d3fd-4d29-b2ce-95f8c3a0d351",
        }
        defaults.update(kwargs)
        return FlowRecord.objects.create(**defaults)

    def test_rule_gate_requires_five_packets_and_xgboost_confidence(self):
        agent = self._agent()
        with (
            patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True),
            patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT", True),
        ):
            self._flow(agent, "few", packet_count=4)
            self.assertEqual(_get_flow_restrictions(agent), [])
            self._flow(agent, "heuristic", classification_engine="Heuristics")
            self.assertEqual(_get_flow_restrictions(agent), [])
            self._flow(agent, "low-confidence", classification_confidence=0.79)
            self.assertEqual(_get_flow_restrictions(agent), [])
            flow = self._flow(agent, "qualified")
            event = {
                "event_id": flow.demo_event_id,
                "source_ip": str(agent.ip_address),
                "receiver_ip": flow.first_dst_ip,
                "receiver_port": flow.first_dst_port,
                "expires_at": time.time() + 60,
            }
            restrictions = _get_flow_restrictions(agent, event)

        self.assertEqual(len(restrictions), 1)
        self.assertEqual(restrictions[0]["src_ip"], str(agent.ip_address))
        self.assertEqual(restrictions[0]["classification_engine"], "XGBoost ML Engine")
        self.assertEqual(restrictions[0]["demo_event_id"], flow.demo_event_id)

    def test_demo_rules_are_private_receiver_scoped_and_demo_opted_in(self):
        agent = self._agent()
        private_flow = self._flow(agent, "private")
        public_flow = self._flow(
            agent,
            "public",
            first_dst_ip="8.8.8.8",
            first_dst_port=53,
            demo_event_id="9c1a55f6-0a0a-4a87-9293-f9a4c1540ee1",
        )
        event = {
            "event_id": private_flow.demo_event_id,
            "source_ip": str(agent.ip_address),
            "receiver_ip": private_flow.first_dst_ip,
            "receiver_port": private_flow.first_dst_port,
            "expires_at": time.time() + 60,
        }
        with (
            patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True),
            patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT", False),
        ):
            self.assertEqual(_get_flow_restrictions(agent, event), [])
        with patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True), patch(
            "netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT", True
        ):
            restrictions = _get_flow_restrictions(agent, event)
        self.assertEqual(len(restrictions), 1)
        self.assertEqual(restrictions[0]["dst_ip"], "192.168.1.50")
        self.assertNotEqual(public_flow.demo_event_id, restrictions[0]["demo_event_id"])

    def test_demo_event_validation_requires_short_lived_private_receiver_and_agent_source(self):
        agent = self._agent()
        event = {
            "event_id": "c3a0d6e1-d3fd-4d29-b2ce-95f8c3a0d351",
            "source_ip": str(agent.ip_address),
            "receiver_ip": "192.168.1.50",
            "receiver_port": 45678,
            "expires_at": time.time() + 90,
        }
        with patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT", True):
            self.assertIsNotNone(_validated_demo_event({"demo_event": event}, agent))
            self.assertIsNone(_validated_demo_event({"demo_event": {**event, "receiver_ip": "8.8.8.8"}}, agent))
            self.assertIsNone(_validated_demo_event({"demo_event": {**event, "source_ip": "192.0.2.99"}}, agent))
            self.assertIsNone(_validated_demo_event({"demo_event": {**event, "expires_at": time.time() - 1}}, agent))

    def test_telemetry_demo_tagging_only_marks_exact_captured_event_packets(self):
        agent = self._agent(9)
        event = {
            "event_id": "c3a0d6e1-d3fd-4d29-b2ce-95f8c3a0d351",
            "source_ip": str(agent.ip_address),
            "receiver_ip": "192.168.1.50",
            "receiver_port": 45678,
            "expires_at": time.time() + 90,
        }
        packets = [
            {"src_ip": str(agent.ip_address), "dst_ip": "192.168.1.50", "src_port": 51234, "dst_port": 45678, "protocol": "UDP"},
            {"src_ip": str(agent.ip_address), "dst_ip": "192.168.1.51", "src_port": 51234, "dst_port": 45678, "protocol": "UDP"},
            {"src_ip": str(agent.ip_address), "dst_ip": "192.168.1.50", "src_port": 51234, "dst_port": 45679, "protocol": "UDP"},
            {"src_ip": str(agent.ip_address), "dst_ip": "192.168.1.50", "src_port": 51234, "dst_port": 45678, "protocol": "TCP"},
        ]
        with (
            patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True),
            patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_DEMO_FLOW_ENFORCEMENT", True),
            patch("netinsight.dashboard.views.api_views.handle_telemetry_ingestion") as ingest,
        ):
            request = self.client.post(
                "/api/v1/agents/telemetry",
                data={
                    "agent_id": str(agent.id),
                    "stats": {"demo_event": event},
                    "packets": packets,
                },
                content_type="application/json",
            )
        self.assertEqual(request.status_code, 200)
        queued_packets = ingest.call_args.args[2]
        self.assertEqual(len(queued_packets), 1)
        self.assertEqual(queued_packets[0]["demo_event_id"], event["event_id"])

    def test_firewall_rejects_nonlocal_or_invalid_rules_and_installs_exact_rule(self):
        rule = {
            "src_ip": "192.0.2.41",
            "src_port": 51234,
            "dst_ip": "198.51.100.22",
            "dst_port": 443,
            "protocol": "TCP",
            "threat_label": "Reconnaissance",
        }
        with (
            patch("agent.flow_firewall.platform.system", return_value="Windows"),
            patch.object(WindowsFlowFirewall, "_run_powershell") as run_powershell,
        ):
            firewall = WindowsFlowFirewall(enabled=True, local_ip="192.0.2.41")
            run_powershell.reset_mock()
            firewall.sync([rule, {**rule, "src_ip": "192.0.2.99"}])
            run_powershell.assert_called_once()
            command = run_powershell.call_args.args[0]
            self.assertIn("-Direction Outbound -Action Block", command)
            self.assertIn("-RemoteAddress '198.51.100.22'", command)
            self.assertEqual(len(firewall.active_rules()), 1)
            firewall.stop()
