import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from netinsight.analytics.engine import AnalyticsEngine
from netinsight.config import settings
from netinsight.database import db_manager


class TestAnalyticsEngine(unittest.TestCase):

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

        protocols = self.engine.get_protocol_distribution()
        self.assertTrue(protocols.empty)

        consumers = self.engine.get_top_consumers()
        self.assertTrue(consumers.empty)

        active_count = self.engine.get_active_devices_count()
        self.assertEqual(active_count, 0)

        summary = self.engine.get_general_summary()
        self.assertEqual(summary["total_packets"], 0)
        self.assertEqual(summary["total_bytes"], 0)

    def test_analytics_calculations(self):
        """Saves known packets to SQLite and verifies Pandas metrics aggregation calculations."""
        now = time.time()

        # Save a set of mock packets
        mock_packets = [
            # 3 TCP packets from IP 192.168.1.5 (total size: 2500 bytes)
            {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "src_port": 5000, "dst_port": 80, "protocol": "TCP", "size": 1000, "timestamp": now - 5, "ttl": 64},
            {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "src_port": 5000, "dst_port": 80, "protocol": "TCP", "size": 1000, "timestamp": now - 4, "ttl": 64},
            {"src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "src_port": 5001, "dst_port": 80, "protocol": "TCP", "size": 500, "timestamp": now - 3, "ttl": 64},
            # 2 UDP packets from IP 192.168.1.10 (total size: 600 bytes)
            {"src_ip": "192.168.1.10", "dst_ip": "1.1.1.1", "src_port": 6000, "dst_port": 53, "protocol": "UDP", "size": 300, "timestamp": now - 2, "ttl": 64},
            {"src_ip": "192.168.1.10", "dst_ip": "1.1.1.1", "src_port": 6000, "dst_port": 53, "protocol": "UDP", "size": 300, "timestamp": now - 1, "ttl": 64},
            # 1 ICMP packet from IP 192.168.1.15 (total size: 100 bytes)
            {"src_ip": "192.168.1.15", "dst_ip": "192.168.1.1", "src_port": 0, "dst_port": 0, "protocol": "ICMP", "size": 100, "timestamp": now, "ttl": 128}
        ]

        db_manager.save_packets_bulk(mock_packets)

        # Test active device count
        active_count = self.engine.get_active_devices_count(window_seconds=10)
        self.assertEqual(active_count, 3) # IPs: 192.168.1.5, 192.168.1.10, 192.168.1.15

        # Test protocol distribution
        proto_df = self.engine.get_protocol_distribution(window_seconds=10)
        self.assertFalse(proto_df.empty)

        # Verify counts
        tcp_row = proto_df[proto_df["protocol"] == "TCP"].iloc[0]
        udp_row = proto_df[proto_df["protocol"] == "UDP"].iloc[0]
        icmp_row = proto_df[proto_df["protocol"] == "ICMP"].iloc[0]

        self.assertEqual(tcp_row["packet_count"], 3)
        self.assertEqual(udp_row["packet_count"], 2)
        self.assertEqual(icmp_row["packet_count"], 1)

        self.assertEqual(tcp_row["percentage"], 50.0) # 3 / 6 * 100
        self.assertAlmostEqual(udp_row["percentage"], 100.0/3, places=5) # 2 / 6 * 100

        # Test top consumers
        consumer_df = self.engine.get_top_consumers(limit=5, window_seconds=10)
        self.assertFalse(consumer_df.empty)

        # 192.168.1.5 should be the top consumer with 2500 bytes
        top_ip_row = consumer_df.iloc[0]
        self.assertEqual(top_ip_row["src_ip"], "192.168.1.5")
        self.assertEqual(top_ip_row["total_bytes"], 2500)

        # Test general summary
        summary = self.engine.get_general_summary(window_seconds=10)
        self.assertEqual(summary["total_packets"], 6)
        self.assertEqual(summary["total_bytes"], 3200)
        self.assertAlmostEqual(summary["avg_packet_size"], 3200.0 / 6, places=2)

if __name__ == "__main__":
    unittest.main()
