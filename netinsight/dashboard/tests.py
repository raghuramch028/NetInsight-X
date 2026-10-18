import time
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from netinsight.analytics.dse import DecisionSupportEngine
from netinsight.analytics.telemetry_handler import (
    _execute_async_telemetry_worker,
    handle_telemetry_ingestion,
)
from netinsight.dashboard.models import Agent, MetricRecord, PacketRecord, SystemSettings


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
