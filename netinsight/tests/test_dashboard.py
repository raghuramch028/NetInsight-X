import os
import unittest
import tempfile
from pathlib import Path
from django.test import SimpleTestCase, Client
from django.urls import reverse

# Setup temporary environment variables to point to test model paths
test_db_dir = tempfile.TemporaryDirectory()
os.environ["NETINSIGHT_DB_PATH"] = str(Path(test_db_dir.name) / "test_netinsight_dashboard.db")
os.environ["NETINSIGHT_DEMO_MODE"] = "True"
os.environ["DJANGO_SETTINGS_MODULE"] = "netinsight.config.settings"

import django
django.setup()

from netinsight.database import db_manager

class TestDashboardViews(SimpleTestCase):
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        db_manager.init_db()
        db_manager.clear_db()
        cls.client = Client()

    @classmethod
    def tearDownClass(cls):
        db_manager.clear_db()
        super().tearDownClass()

    def test_routing_and_views_http_status(self):
        """Verifies that all subpages render HTTP 200 Success."""
        views_to_test = [
            ("dashboard:index", {}),
            ("dashboard:analytics", {}),
            ("dashboard:optimization", {}),
            ("dashboard:prediction", {}),
            ("dashboard:classification", {}),
            ("dashboard:reports", {})
        ]
        
        for view_name, kwargs in views_to_test:
            url = reverse(view_name, kwargs=kwargs)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, f"Failed rendering view {view_name} at URL {url}")

    def test_json_api_endpoints(self):
        """Verifies the JSON APIs for Chart.js and packet logs return expected structures."""
        # Test Live Metrics API
        url_metrics = reverse("dashboard:api_live_metrics")
        response = self.client.get(url_metrics)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        self.assertIn("throughput", data)
        self.assertIn("packet_rate", data)
        self.assertIn("bandwidth_util", data)
        self.assertIn("latency", data)
        self.assertIn("packet_loss", data)
        self.assertIn("network_state", data)
        
        # Test Live Packets API
        url_packets = reverse("dashboard:api_live_packets")
        response = self.client.get(url_packets)
        self.assertEqual(response.status_code, 200)
        pkts_data = response.json()
        self.assertIn("packets", pkts_data)
        self.assertIsInstance(pkts_data["packets"], list)
