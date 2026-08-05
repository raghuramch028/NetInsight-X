import os
import time
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")
os.environ["DATABASE_URL"] = ""

import django

django.setup()

from django.test import Client

from netinsight.classification.classifier import TrafficClassifier
from netinsight.optimization.solver import BandwidthOptimizer
from netinsight.prediction.hmm import HiddenMarkovModel
from netinsight.prediction.mdp import MDPRecommendationEngine


class TestClosedLoopScenarios(unittest.TestCase):

    def setUp(self):
        self.client = Client()
        self.optimizer = BandwidthOptimizer()
        self.hmm = HiddenMarkovModel()
        self.mdp = MDPRecommendationEngine()
        self.classifier = TrafficClassifier()
        self.mac = "00:1A:2B:3C:4D:5E"
        self.hostname = "Test-Host-01"

    def test_case_1_baseline_normal_traffic(self):
        """Test Case 1: Baseline 100 Mbps link with normal web browsing traffic."""
        print("\n[TEST CASE 1] Running Baseline Normal Traffic Test...")
        # 1. Register agent
        reg = self.client.post("/api/v1/agents/register", {
            "mac_address": self.mac,
            "hostname": self.hostname,
            "device_type": "Windows 11",
            "vendor": "Dell"
        }, content_type="application/json")
        self.assertEqual(reg.status_code, 200)

        # 2. Classify normal packet
        pkt = {
            "src_ip": "192.168.1.50", "dst_ip": "104.16.123.96",
            "src_port": 54321, "dst_port": 443, "protocol": "TCP",
            "size": 600, "timestamp": time.time(), "latency_est": 0.012
        }
        threat = self.classifier.classify_packet(pkt)
        self.assertEqual(threat, "Normal")

        # 3. Solve LP Allocation at 100 Mbps
        result = self.optimizer.solve_allocation(total_capacity=100e6)
        self.assertIn("optimal", result["status"])
        self.assertGreater(result["allocations"][0], 0)
        print("  [OK] Test Case 1 PASSED: Baseline 100 Mbps LP solution optimal & threat classified Normal.")

    def test_case_2_mobile_hotspot_capacity_scaling(self):
        """Test Case 2: Mobile Hotspot (8.5 Mbps link capacity) dynamic bound scaling."""
        print("\n[TEST CASE 2] Running Mobile Hotspot Bounds Scaling Test (8.5 Mbps)...")
        capacity_bps = 8.5e6
        ratio = capacity_bps / 100e6
        active_min = [5e6 * ratio, 15e6 * ratio, 2e6 * ratio, 10e6 * ratio]
        active_max = [40e6 * ratio, 60e6 * ratio, 30e6 * ratio, 50e6 * ratio]

        result = self.optimizer.solve_allocation(
            min_bounds=active_min, max_bounds=active_max, total_capacity=capacity_bps
        )
        self.assertIn("optimal", result["status"])
        total_allocated = sum(result["allocations"])
        self.assertLessEqual(total_allocated, capacity_bps + 1.0)
        print(f"  [OK] Test Case 2 PASSED: 8.5 Mbps LP solver optimal! Allocated {total_allocated/1e6:.2f} Mbps.")

    def test_case_3_ddos_attack_incident_response(self):
        """Test Case 3: High packet rate DDoS attack detection and MDP policy override."""
        print("\n[TEST CASE 3] Running DDoS Attack Incident Response Test...")
        # 1. High rate packet
        pkt = {
            "src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
            "src_port": 60000, "dst_port": 5004, "protocol": "UDP",
            "size": 100, "timestamp": time.time(), "packet_rate": 1500.0, "conn_frequency": 5.0
        }
        threat = self.classifier.classify_packet(pkt)
        self.assertIn(threat, ["DDoS", "DoS", "Mirai"])

        # 2. HMM Log-Space Viterbi decoding under attack metrics
        obs = [{"util": 85.0, "latency": 0.350, "loss": 15.0, "packet_rate": 1200.0, "sockets": 150.0, "threat_label": "DDoS"}]
        states = self.hmm.decode_states(obs)
        self.assertEqual(states[0], "Under Attack")

        # 3. MDP Policy Selection
        mdp_res = self.mdp.get_recommendation("Under Attack")
        self.assertEqual(mdp_res["recommended_action"], "Prioritize Critical Services")
        print(f"  [OK] Test Case 3 PASSED: Threat='{threat}', HMM State='{states[0]}', MDP='{mdp_res['recommended_action']}'.")

    def test_case_4_port_scan_reconnaissance_detection(self):
        """Test Case 4: High connection frequency Reconnaissance / Port Scan detection."""
        print("\n[TEST CASE 4] Running Reconnaissance / Port Scan Test...")
        pkt = {
            "src_ip": "192.168.1.200", "dst_ip": "10.0.0.5",
            "src_port": 40000, "dst_port": 22, "protocol": "TCP",
            "size": 64, "timestamp": time.time(), "packet_rate": 60.0, "conn_frequency": 60.0
        }
        threat = self.classifier.classify_packet(pkt)
        self.assertIn(threat, ["Reconnaissance", "Brute Force"])
        print(f"  [OK] Test Case 4 PASSED: Port scan classified as '{threat}'.")

    def test_case_5_closed_loop_telemetry_ingest_endpoint(self):
        """Test Case 5: End-to-end /api/v1/agents/telemetry API closed-loop response."""
        print("\n[TEST CASE 5] Running Telemetry API Closed-Loop Ingest Test...")
        reg = self.client.post("/api/v1/agents/register", {
            "mac_address": self.mac, "hostname": self.hostname, "device_type": "Windows 11", "vendor": "Dell"
        }, content_type="application/json")
        self.assertEqual(reg.status_code, 200)
        agent_id = reg.json()["agent_id"]

        payload = {
            "agent_id": agent_id,
            "mac_address": self.mac,
            "hostname": self.hostname,
            "stats": {
                "bytes_sent": 500000, "bytes_recv": 2000000, "active_connections": 10,
                "packet_rate": 150.0, "avg_latency": 0.025, "packet_loss": 0.5
            },
            "packets": [{
                "src_ip": "192.168.1.50", "dst_ip": "104.16.123.96",
                "src_port": 54321, "dst_port": 443, "protocol": "TCP",
                "size": 600, "ttl": 64, "timestamp": time.time()
            }]
        }
        res = self.client.post("/api/v1/agents/telemetry", payload, content_type="application/json", follow=True)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("enforced_qos", data)
        self.assertIn("web_browsing_mbps", data["enforced_qos"])
        print("  [OK] Test Case 5 PASSED: Telemetry API returned HTTP 200 OK with enforced Mbps caps.")

if __name__ == "__main__":
    unittest.main()
