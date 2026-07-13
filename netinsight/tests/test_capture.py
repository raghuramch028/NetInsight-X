import os
import time
import unittest
import tempfile
import logging
from pathlib import Path
from scapy.all import IP, TCP, UDP

logger = logging.getLogger(__name__)

# Force temporary database path for testing
test_db_dir = tempfile.TemporaryDirectory()
os.environ["NETINSIGHT_DB_PATH"] = str(Path(test_db_dir.name) / "test_netinsight.db")
os.environ["NETINSIGHT_DEMO_MODE"] = "True"

from netinsight.config import settings
from netinsight.capture.parser import PacketParser
from netinsight.capture.monitor import LiveMonitor
from netinsight.database import db_manager

class TestPacketCapture(unittest.TestCase):
    
    def setUp(self):
        # Initialize database schema on temporary file
        db_manager.init_db()
        db_manager.clear_db()
        self.parser = PacketParser()

    def tearDown(self):
        db_manager.clear_db()

    def test_settings_load(self):
        """Verifies configuration constants load properly."""
        self.assertEqual(settings.LINK_CAPACITY, 100_000_000.0)
        self.assertTrue(settings.DEMO_MODE)
        self.assertIn("NORMAL", settings.STATE_THRESHOLDS)

    def test_tcp_packet_parsing(self):
        """Tests standard TCP packet parameter extraction."""
        # Create a mock Scapy IP/TCP packet
        pkt = IP(src="192.168.1.50", dst="10.0.0.1", ttl=64) / TCP(sport=12345, dport=80, seq=1000, flags="S")
        pkt.time = time.time()
        
        parsed = self.parser.parse(pkt)
        
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["src_ip"], "192.168.1.50")
        self.assertEqual(parsed["dst_ip"], "10.0.0.1")
        self.assertEqual(parsed["src_port"], 12345)
        self.assertEqual(parsed["dst_port"], 80)
        self.assertEqual(parsed["protocol"], "TCP")
        self.assertEqual(parsed["ttl"], 64)
        self.assertFalse(parsed["is_retransmission"])

    def test_tcp_rtt_latency_approximation(self):
        """Tests handshake RTT calculation logic."""
        # 1. Client SYN
        t_syn = time.time()
        pkt1 = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=1000, flags="S")
        pkt1.time = t_syn
        self.parser.parse(pkt1)

        # 2. Server SYN-ACK (arrives 50ms later)
        t_syn_ack = t_syn + 0.050
        pkt2 = IP(src="10.0.0.1", dst="192.168.1.50") / TCP(sport=80, dport=12345, seq=5000, ack=1001, flags="SA")
        pkt2.time = t_syn_ack
        parsed2 = self.parser.parse(pkt2)
        
        # Check parser RTT calculation
        self.assertIsNotNone(parsed2["latency_est"])
        self.assertAlmostEqual(parsed2["latency_est"], 0.050, places=3)

    def test_tcp_packet_loss_retransmission_heuristic(self):
        """Tests packet loss detection using TCP retransmissions."""
        flow_pkt1 = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=2000, flags="A")
        # Scapy payload length > 0 is needed to trigger seq tracker checks
        flow_pkt1 = flow_pkt1 / "SOME PAYLOAD DATA"
        flow_pkt1.time = time.time()
        
        parsed1 = self.parser.parse(flow_pkt1)
        self.assertFalse(parsed1["is_retransmission"])
        
        # Identical packet (duplicate sequence number) signifying a TCP retransmission
        flow_pkt2 = IP(src="192.168.1.50", dst="10.0.0.1") / TCP(sport=12345, dport=80, seq=2000, flags="A")
        flow_pkt2 = flow_pkt2 / "SOME PAYLOAD DATA"
        flow_pkt2.time = time.time() + 0.1
        
        parsed2 = self.parser.parse(flow_pkt2)
        self.assertTrue(parsed2["is_retransmission"])
        self.assertAlmostEqual(self.parser.get_estimated_loss_rate(), 50.0, places=1)

    def test_live_monitor_demo_run(self):
        """Starts and stops LiveMonitor in DEMO_MODE, verifying packets flow to SQL."""
        monitor = LiveMonitor()
        monitor.start()
        
        # Let it run for 1.5 seconds to accumulate packets and write to SQL
        time.sleep(1.5)
        monitor.stop()
        
        # Check that packets were inserted into the DB
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM packets")
        packet_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM metrics")
        metrics_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM state_history")
        history_count = cursor.fetchone()[0]
        
        conn.close()
        
        self.assertGreater(packet_count, 0, "Packets table should have entries in Demo Mode.")
        logger.info(f"Test Run Summary: Captured {packet_count} packets and generated {metrics_count} metric logs.")

if __name__ == "__main__":
    unittest.main()
