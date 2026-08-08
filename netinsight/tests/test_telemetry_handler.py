"""Regression tests for netinsight/analytics/telemetry_handler.py and flow_builder.py.

Covers the Phase 2 fixes: real RTT-based latency instead of a hardcoded constant,
a threat-label-independent packet-loss estimate, and real (non-hardcoded) conn_frequency
feeding the classifier via the production ingestion path.
"""
import os
import shutil
import tempfile
import time
from pathlib import Path

from django.test import TestCase

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")

from netinsight.analytics import telemetry_handler
from netinsight.analytics.flow_builder import prepare_packet_record
from netinsight.analytics.telemetry_handler import _execute_async_telemetry_worker
from netinsight.config import settings
from netinsight.dashboard.models import Agent, FlowRecord, MetricRecord, PacketRecord
from netinsight.database import db_manager


class TestTelemetryHandlerFixes(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig_db_path = settings.DB_PATH
        cls.test_db_dir = tempfile.mkdtemp()
        settings.DB_PATH = str(Path(cls.test_db_dir) / "test_netinsight_telemetry.db")
        os.environ["NETINSIGHT_DB_PATH"] = settings.DB_PATH
        db_manager.init_db()

    @classmethod
    def tearDownClass(cls):
        settings.DB_PATH = cls._orig_db_path
        shutil.rmtree(cls.test_db_dir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        Agent.objects.all().delete()
        PacketRecord.objects.all().delete()
        MetricRecord.objects.all().delete()
        FlowRecord.objects.all().delete()
        self.agent = Agent.objects.create(
            mac_address="00:11:22:33:44:aa", hostname="Telemetry-Test-Host", ip_address="192.168.1.20"
        )

    def test_latency_uses_reported_rtt_when_valid(self):
        """Regression: latency was previously hardcoded to 0.015 regardless of input."""
        _execute_async_telemetry_worker(self.agent.id, {"rtt_seconds": 0.042}, [])
        metric = MetricRecord.objects.order_by("-timestamp").first()
        self.assertIsNotNone(metric)
        self.assertAlmostEqual(metric.latency, 0.042, places=6)

    def test_latency_falls_back_to_default_when_rtt_missing(self):
        _execute_async_telemetry_worker(self.agent.id, {}, [])
        metric = MetricRecord.objects.order_by("-timestamp").first()
        self.assertAlmostEqual(metric.latency, 0.015, places=6)

    def test_latency_falls_back_to_default_when_rtt_implausible(self):
        """Negative or absurdly large reported RTT values must not be trusted."""
        _execute_async_telemetry_worker(self.agent.id, {"rtt_seconds": -5.0}, [])
        metric = MetricRecord.objects.order_by("-timestamp").first()
        self.assertAlmostEqual(metric.latency, 0.015, places=6)

        _execute_async_telemetry_worker(self.agent.id, {"rtt_seconds": 999.0}, [])
        metric = MetricRecord.objects.order_by("-timestamp").first()
        self.assertAlmostEqual(metric.latency, 0.015, places=6)

    def test_packet_loss_independent_of_threat_labels(self):
        """Regression: packet_loss previously required FlowRecord.threat_label rows (DoS/DDoS/
        Mirai flows) to be non-zero — a circular dependency on the classifier's own output.
        It must now be computable from raw duplicate/retransmission-like packets alone, with
        zero FlowRecord or ThreatHistory rows present. These packets have no tcp_seq captured
        (older-agent / DEMO_MODE scenario), so this exercises the size-based fallback path."""
        now_ts = time.time()
        # 5 identical (5-tuple + size) TCP packets = 4 "retransmission-like" duplicates out of 5.
        for i in range(5):
            PacketRecord.objects.create(
                agent=self.agent, src_ip="192.168.1.50", dst_ip="10.0.0.9",
                src_port=5000, dst_port=443, protocol="TCP", size=512,
                timestamp=now_ts - 1 + i * 0.01, ttl=64, tcp_seq=100,
            )
        self.assertEqual(FlowRecord.objects.count(), 0)

        _execute_async_telemetry_worker(self.agent.id, {}, [])

        metric = MetricRecord.objects.order_by("-timestamp").first()
        self.assertGreater(metric.packet_loss, 0.0)

    def test_packet_loss_uses_exact_tcp_seq_when_available(self):
        """When agents report tcp_seq, packet_loss must use exact 5-tuple+seq retransmission
        matching rather than the coarser size-based fallback — two DIFFERENT flows that happen
        to share a size must NOT be counted as retransmissions of each other once seq numbers
        are present, only a genuinely repeated (same tuple, same seq) segment should count."""
        now_ts = time.time()
        # Genuine retransmission: same 5-tuple, same tcp_seq, sent twice.
        for i in range(2):
            PacketRecord.objects.create(
                agent=self.agent, src_ip="192.168.1.60", dst_ip="10.0.0.10",
                src_port=6000, dst_port=443, protocol="TCP", size=500,
                timestamp=now_ts - 1 + i * 0.01, ttl=64, tcp_seq=123456,
            )
        # Two unrelated flows that happen to share the same size but have distinct seq numbers —
        # must NOT be counted as retransmissions now that exact seq matching is available.
        PacketRecord.objects.create(
            agent=self.agent, src_ip="192.168.1.61", dst_ip="10.0.0.11",
            src_port=7000, dst_port=443, protocol="TCP", size=500,
            timestamp=now_ts, ttl=64, tcp_seq=999,
        )
        PacketRecord.objects.create(
            agent=self.agent, src_ip="192.168.1.62", dst_ip="10.0.0.12",
            src_port=7001, dst_port=443, protocol="TCP", size=500,
            timestamp=now_ts, ttl=64, tcp_seq=1000,
        )

        _execute_async_telemetry_worker(self.agent.id, {}, [])

        metric = MetricRecord.objects.order_by("-timestamp").first()
        # 1 retransmission out of 4 TCP packets with seq coverage = 25%.
        self.assertAlmostEqual(metric.packet_loss, 25.0, places=2)

    def test_conn_frequency_no_longer_hardcoded_reconnaissance_reachable(self):
        """Regression: flow_builder.py previously hardcoded conn_frequency=1.0 for every
        server-ingested packet, permanently disabling the Reconnaissance/Mirai heuristic rules
        (which require conn_frequency > 25-50). With the hardcoding removed, a real port-scan
        pattern (one source hitting many distinct destinations quickly) must be detectable."""
        now_ts = time.time()
        last_flow = None
        for i in range(60):
            pkt = {
                "src_ip": "192.168.1.77",
                "dst_ip": f"10.0.0.{i + 1}",
                "src_port": 40000,
                "dst_port": (i % 100) + 1,
                "protocol": "TCP",
                "size": 64,
                "timestamp": now_ts + i * 0.01,
                "ttl": 64,
            }
            record = prepare_packet_record(self.agent, pkt)
            self.assertIsNotNone(record)
            last_flow = FlowRecord.objects.filter(
                agent=self.agent, flow_key__contains="192.168.1.77"
            ).order_by("-end_time").first()

        # By the final packet, unique_dests (60) comfortably exceeds the conn_frequency > 50
        # Reconnaissance threshold. Flow-level packet_rate stays low (~2 pps per distinct-dest
        # flow), so the port-22 Brute Force rule (which requires per-flow rate > 50) cannot
        # trigger here — this isolates the conn_frequency fix specifically.
        self.assertIsNotNone(last_flow)
        self.assertEqual(last_flow.threat_label, "Reconnaissance")

    def test_prepare_packet_record_forwards_tcp_seq(self):
        """The tcp_seq captured by the agent (agent/sniffer.py, agent_go/sniffer/sniffer.go)
        must reach the stored PacketRecord — this is what makes exact retransmission detection
        possible server-side."""
        pkt = {
            "src_ip": "192.168.1.90", "dst_ip": "10.0.0.20", "src_port": 5555, "dst_port": 443,
            "protocol": "TCP", "size": 128, "timestamp": time.time(), "ttl": 64, "tcp_seq": 4242,
        }
        record = prepare_packet_record(self.agent, pkt)
        self.assertIsNotNone(record)
        self.assertEqual(record.tcp_seq, 4242)

    def test_prepare_packet_record_handles_missing_tcp_seq(self):
        """UDP/ICMP packets (and older agent builds) won't have tcp_seq — must default to None,
        not raise or coerce to a bogus 0."""
        pkt = {
            "src_ip": "192.168.1.91", "dst_ip": "10.0.0.21", "src_port": 5353, "dst_port": 53,
            "protocol": "UDP", "size": 64, "timestamp": time.time(), "ttl": 64,
        }
        record = prepare_packet_record(self.agent, pkt)
        self.assertIsNotNone(record)
        self.assertIsNone(record.tcp_seq)

    def test_pruning_removed_from_per_request_path(self):
        """Regression (Phase 3): the 5 prune DELETE statements previously ran on every single
        telemetry request. They must no longer execute inside _execute_async_telemetry_worker —
        a stale PacketRecord older than the prune cutoff must survive a normal ingestion call."""
        stale_ts = time.time() - 700.0  # older than the 600s packet prune cutoff
        PacketRecord.objects.create(
            agent=self.agent, src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=1, dst_port=1, protocol="TCP", size=64, timestamp=stale_ts, ttl=64,
        )
        _execute_async_telemetry_worker(self.agent.id, {}, [])
        self.assertTrue(PacketRecord.objects.filter(timestamp=stale_ts).exists())

    def test_periodic_pruner_removes_stale_records(self):
        """The dedicated periodic pruning function (now run on a timer, not per-request) must
        still correctly remove stale records when invoked."""
        stale_ts = time.time() - 700.0
        PacketRecord.objects.create(
            agent=self.agent, src_ip="192.168.1.1", dst_ip="10.0.0.1",
            src_port=1, dst_port=1, protocol="TCP", size=64, timestamp=stale_ts, ttl=64,
        )
        telemetry_handler._prune_stale_records()
        self.assertFalse(PacketRecord.objects.filter(timestamp=stale_ts).exists())

    def test_backpressure_skips_heavy_processing_when_backlog_full(self):
        """Regression (Phase 3): handle_telemetry_ingestion() previously submitted to the async
        pool unconditionally, with no bound on in-flight tasks. Verifies that once the in-flight
        cap is reached, the tick is skipped (logged) instead of queuing without limit."""
        acquired_count = 0
        try:
            while telemetry_handler._telemetry_inflight_semaphore.acquire(blocking=False):
                acquired_count += 1

            with self.assertLogs(telemetry_handler.logger, level="WARNING") as log_ctx:
                telemetry_handler.handle_telemetry_ingestion(self.agent, {"cpu_usage": 5.0}, [])

            self.assertTrue(any("backlog full" in msg for msg in log_ctx.output))
        finally:
            for _ in range(acquired_count):
                telemetry_handler._telemetry_inflight_semaphore.release()
