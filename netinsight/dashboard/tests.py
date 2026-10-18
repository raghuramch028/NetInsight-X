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
from netinsight.dashboard.views.api_views import _get_flow_restrictions


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
            active_flow_blocks=[{"dst_ip": "198.51.100.10", "dst_port": 23, "protocol": "TCP"}],
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
                protocol="TCP",
                threat_label="Reconnaissance",
                policy_action="RESTRICT_FLOW",
                policy_estimated_reclaimed_bps=2_000_000.0,
            )

        with patch("netinsight.analytics.dse.app_settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True):
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
                policy_action="RESTRICT_FLOW",
                policy_estimated_reclaimed_bps=8000.0,
            )

        alert_ids = {alert["id"] for alert in self._evaluate()}
        self.assertNotIn("alert-flow-response", alert_ids)
        self.assertIn("alert-flow-monitor", alert_ids)


class FlowEnforcementTests(TestCase):
    def _agent(self):
        return Agent.objects.create(
            mac_address="02:00:00:00:03:01",
            hostname="demo-host",
            ip_address="192.0.2.41",
            device_type="Windows",
            vendor="Test",
        )

    def _packet(self, agent, port, label="Reconnaissance", src_ip=None):
        return PacketRecord.objects.create(
            agent=agent,
            src_ip=src_ip or agent.ip_address,
            dst_ip="198.51.100.22",
            src_port=50000 + port,
            dst_port=port,
            protocol="TCP",
            size=100,
            ttl=64,
            timestamp=time.time(),
            threat_label=label,
        )

    def test_api_rule_gate_requires_five_suspicious_outbound_packets(self):
        agent = self._agent()
        with patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True):
            for port in range(4, 8):
                self._packet(agent, 20 + port)
            self.assertEqual(_get_flow_restrictions(agent), [])

            self._packet(agent, 28)
            restrictions = _get_flow_restrictions(agent)

        self.assertEqual(len(restrictions), 5)
        self.assertTrue(all(rule["src_ip"] == str(agent.ip_address) for rule in restrictions))
        self.assertEqual(restrictions[0]["protocol"], "TCP")

    def test_api_never_returns_another_hosts_or_unclassified_flows(self):
        agent = self._agent()
        with patch("netinsight.dashboard.views.api_views.settings.NETINSIGHT_ENABLE_FLOW_ENFORCEMENT", True):
            for port in range(5):
                self._packet(agent, 100 + port, src_ip="192.0.2.99")
            self.assertEqual(_get_flow_restrictions(agent), [])

            PacketRecord.objects.filter(agent=agent).delete()
            for port in range(5):
                self._packet(agent, 200 + port, label="Normal")
            self.assertEqual(_get_flow_restrictions(agent), [])

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
