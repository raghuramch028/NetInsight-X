import os
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")

import django

django.setup()

from django.test import Client, TestCase
from django.urls import reverse

from netinsight.dashboard.demo_scenarios import trigger_scenario


class TestDemoScenarios(TestCase):

    def setUp(self):
        self.client = Client()

    def test_scenario_0_reset_to_live(self):
        """Verifies Scenario 0 resets database state back to live baseline."""
        res = trigger_scenario(0)
        self.assertEqual(res["scenario_id"], 0)
        self.assertEqual(res["threat_type"], "Normal")
        self.assertEqual(res["hmm_state"], "Normal")

    def test_scenario_1_normal_baseline(self):
        """Verifies Scenario 1 triggers baseline 100 Mbps execution pipeline."""
        res = trigger_scenario(1)
        self.assertEqual(res["scenario_id"], 1)
        self.assertEqual(res["threat_type"], "Normal")
        self.assertIn("optimal", res["lp_status"])
        self.assertTrue(res["kkt_optimal"])

    def test_scenario_2_ddos_incident_response(self):
        """Verifies Scenario 2 triggers DDoS volumetric attack response."""
        res = trigger_scenario(2)
        self.assertEqual(res["scenario_id"], 2)
        self.assertEqual(res["threat_type"], "DDoS")
        self.assertEqual(res["hmm_state"], "Under Attack")
        self.assertEqual(res["mdp_action"], "Prioritize Critical Services")
        self.assertIn("optimal", res["lp_status"])

    def test_scenario_3_mobile_hotspot_scaling(self):
        """Verifies Scenario 3 triggers 8.5 Mbps capacity scaling."""
        res = trigger_scenario(3)
        self.assertEqual(res["scenario_id"], 3)
        self.assertAlmostEqual(res["link_capacity_mbps"], 8.5, places=1)
        self.assertIn("optimal", res["lp_status"])
        self.assertTrue(res["kkt_optimal"])

    def test_api_trigger_scenario_endpoint(self):
        """Verifies /api/v1/demo/trigger REST API returns HTTP 200 OK and scenario metadata."""
        url = reverse("dashboard:api_trigger_scenario")
        res = self.client.post(url, {"scenario_id": 2}, content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("scenario", data)
        self.assertEqual(data["scenario"]["threat_type"], "DDoS")

    def test_api_trigger_scenario_reset_endpoint(self):
        """Verifies /api/v1/demo/trigger REST API with scenario_id=0 resets DB state."""
        url = reverse("dashboard:api_trigger_scenario")
        res = self.client.post(url, {"scenario_id": 0}, content_type="application/json")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["scenario"]["scenario_id"], 0)


if __name__ == "__main__":
    unittest.main()
