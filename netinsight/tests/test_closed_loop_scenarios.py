import os
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")
os.environ["DATABASE_URL"] = ""

import django

django.setup()

from django.test import Client

from netinsight.optimization.solver import BandwidthOptimizer


class TestClosedLoopScenarios(unittest.TestCase):

    def setUp(self):
        self.client = Client()
        self.optimizer = BandwidthOptimizer()
        self.mac = "00:1a:2b:3c:4d:5e"
        self.hostname = "Test-Host-01"

    def test_case_1_baseline_normal_traffic(self):
        """Test Case 1: Baseline 100 Mbps link with standard QoS classes."""
        print("\n[TEST CASE 1] Running Baseline Normal Traffic Optimization Test...")
        reg = self.client.post("/api/v1/agents/register", {
            "mac_address": self.mac,
            "hostname": self.hostname,
            "device_type": "Windows 11",
            "vendor": "Dell"
        }, content_type="application/json")
        self.assertEqual(reg.status_code, 200)

        result = self.optimizer.solve_allocation(total_capacity=100e6)
        self.assertIn("optimal", result["status"])
        self.assertGreater(result["allocations"][0], 0)
        total_allocated = sum(result["allocations"])
        self.assertAlmostEqual(total_allocated, 100e6, places=-2)
        print(f"  [OK] Test Case 1 PASSED: Baseline 100 Mbps LP solution optimal (Allocated: {total_allocated/1e6:.2f} Mbps).")

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

    def test_case_3_multi_device_partitioning(self):
        """Test Case 3: Dynamic multi-device equal capacity partitioning."""
        print("\n[TEST CASE 3] Running Multi-Device Capacity Partitioning Test...")
        total_link_capacity = 100e6
        active_devices = 4
        device_capacity = total_link_capacity / active_devices  # 25 Mbps each

        ratio = device_capacity / 100e6
        active_min = [5e6 * ratio, 15e6 * ratio, 2e6 * ratio, 10e6 * ratio]
        active_max = [40e6 * ratio, 60e6 * ratio, 30e6 * ratio, 50e6 * ratio]

        result = self.optimizer.solve_allocation(
            min_bounds=active_min, max_bounds=active_max, total_capacity=device_capacity
        )
        self.assertIn("optimal", result["status"])
        total_allocated = sum(result["allocations"])
        self.assertAlmostEqual(total_allocated, device_capacity, places=-2)
        print(f"  [OK] Test Case 3 PASSED: Device allocated {total_allocated/1e6:.2f} Mbps out of {device_capacity/1e6:.2f} Mbps target.")

    def test_case_4_infeasible_fallback_allocation(self):
        """Test Case 4: Structurally infeasible bounds graceful priority-weighted fallback."""
        print("\n[TEST CASE 4] Running Infeasible Bounds Priority Fallback Test...")
        # Min bounds sum to 32 Mbps, but total capacity is only 8.5 Mbps
        result = self.optimizer.solve_allocation(
            priorities=[1.0, 2.0, 0.5, 3.0],
            min_bounds=[5e6, 15e6, 2e6, 10e6],
            max_bounds=[40e6, 60e6, 30e6, 50e6],
            total_capacity=8.5e6
        )
        self.assertIn("infeasible", result["status"])
        total_allocated = sum(result["allocations"])
        self.assertAlmostEqual(total_allocated, 8.5e6, places=-2)
        print(f"  [OK] Test Case 4 PASSED: Graceful fallback allocated full {total_allocated/1e6:.2f} Mbps proportionally.")

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
                "size": 600, "timestamp": 1700000000.0, "ttl": 64, "tcp_seq": 1000
            }]
        }

        resp = self.client.post("/api/v1/agents/telemetry", payload, content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("enforced_qos", data)
        self.assertIn("web_browsing_mbps", data["enforced_qos"])
        print("  [OK] Test Case 5 PASSED: Telemetry API returned HTTP 200 OK with enforced Mbps caps.")


if __name__ == "__main__":
    unittest.main()
