import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from django.test import TestCase

from netinsight.analytics.engine import AnalyticsEngine
from netinsight.config import settings
from netinsight.database import db_manager


class TestAnalyticsEngine(TestCase):

    @classmethod
    def setUpClass(cls):
        cls._orig_db_path = settings.DB_PATH
        cls.test_db_dir = tempfile.mkdtemp()
        settings.DB_PATH = str(Path(cls.test_db_dir) / "test_netinsight_analytics.db")
        os.environ["NETINSIGHT_DB_PATH"] = settings.DB_PATH

    @classmethod
    def tearDownClass(cls):
        settings.DB_PATH = cls._orig_db_path
        shutil.rmtree(cls.test_db_dir, ignore_errors=True)

    def setUp(self):
        db_manager.init_db()
        db_manager.clear_db()
        # Clear Django ORM tables for test isolation (needed with --keepdb)
        from netinsight.dashboard.models import Agent, MetricRecord, PacketRecord
        Agent.objects.all().delete()
        MetricRecord.objects.all().delete()
        PacketRecord.objects.all().delete()
        self.engine = AnalyticsEngine()

    def tearDown(self):
        db_manager.clear_db()

    def test_empty_database_graceful_handling(self):
        """Verifies that the engine returns neutral outputs instead of crashing when DB is empty."""
        metrics = self.engine.get_latest_metrics()
        self.assertEqual(metrics["throughput"], 0.0)
        self.assertEqual(metrics["packet_rate"], 0.0)
        self.assertEqual(metrics["bandwidth_util"], 0.0)

        history = self.engine.get_historical_metrics()
        self.assertTrue(history.empty)

        active_count = self.engine.get_active_devices_count()
        self.assertEqual(active_count, 0)

    def test_analytics_calculations(self):
        """Saves known packets to SQLite and verifies active devices count and metrics recording."""
        now = time.time()
        from django.utils import timezone

        from netinsight.dashboard.models import Agent, PacketRecord

        PacketRecord.objects.all().delete()
        Agent.objects.all().delete()

        # Create active Agent database records first
        agent1 = Agent.objects.create(mac_address="00:11:22:33:44:55", hostname="Agent 1", ip_address="192.168.1.5", last_seen=timezone.now())
        agent2 = Agent.objects.create(mac_address="00:11:22:33:44:66", hostname="Agent 2", ip_address="192.168.1.10", last_seen=timezone.now())
        agent3 = Agent.objects.create(mac_address="00:11:22:33:44:77", hostname="Agent 3", ip_address="192.168.1.15", last_seen=timezone.now())

        # Save a set of mock packets
        mock_packets = [
            {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "src_port": 5000, "dst_port": 80, "protocol": "TCP", "size": 1000, "timestamp": now - 5, "ttl": 64, "agent": agent1},
            {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "src_port": 5000, "dst_port": 80, "protocol": "TCP", "size": 1000, "timestamp": now - 4, "ttl": 64, "agent": agent1},
            {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "src_port": 5001, "dst_port": 80, "protocol": "TCP", "size": 500, "timestamp": now - 3, "ttl": 64, "agent": agent1},
            {"src_ip": "192.168.1.10", "dst_ip": "1.1.1.1", "src_port": 6000, "dst_port": 53, "protocol": "UDP", "size": 300, "timestamp": now - 2, "ttl": 64, "agent": agent2},
            {"src_ip": "192.168.1.10", "dst_ip": "1.1.1.1", "src_port": 6000, "dst_port": 53, "protocol": "UDP", "size": 300, "timestamp": now - 1, "ttl": 64, "agent": agent2},
            {"src_ip": "192.168.1.15", "dst_ip": "192.168.1.1", "src_port": 0, "dst_port": 0, "protocol": "ICMP", "size": 100, "timestamp": now, "ttl": 128, "agent": agent3}
        ]

        db_packets = [PacketRecord(**p) for p in mock_packets]
        PacketRecord.objects.bulk_create(db_packets)

        # Test active device count
        active_count = self.engine.get_active_devices_count(window_seconds=10)
        self.assertEqual(active_count, 3) # IPs: 192.168.1.5, 192.168.1.10, 192.168.1.15

    def test_network_topology_generation(self):
        """Verifies that the PyVis network topology generates HTML output."""
        from netinsight.analytics.topology import generate_topology_pyvis
        html = generate_topology_pyvis()
        self.assertIsNotNone(html)
        self.assertIn("vis.js", html)
        self.assertIn("Phone Hotspot", html)

if __name__ == "__main__":
    unittest.main()
