import os
import shutil
import tempfile
from pathlib import Path

from django.test import Client, SimpleTestCase
from django.urls import reverse

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")

import django

django.setup()

from netinsight.config import settings
from netinsight.database import db_manager


class TestDashboardViews(SimpleTestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig_db_path = settings.DB_PATH
        cls._orig_demo_mode = settings.DEMO_MODE
        cls.test_db_dir = tempfile.mkdtemp()
        settings.DB_PATH = str(Path(cls.test_db_dir) / "test_netinsight_dashboard.db")
        os.environ["NETINSIGHT_DB_PATH"] = settings.DB_PATH
        settings.DEMO_MODE = True
        os.environ["NETINSIGHT_DEMO_MODE"] = "True"
        db_manager.init_db()
        db_manager.clear_db()
        cls.client = Client()

    @classmethod
    def tearDownClass(cls):
        # Stop background monitor thread if it was started
        from netinsight.dashboard import views
        if views.monitor is not None:
            views.monitor.stop()
        db_manager.clear_db()
        settings.DB_PATH = cls._orig_db_path
        settings.DEMO_MODE = cls._orig_demo_mode
        shutil.rmtree(cls.test_db_dir, ignore_errors=True)
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
        self.assertIsInstance(data["bandwidth_util"], (int, float))
        self.assertIn(data["network_state"], ["NORMAL", "BUSY", "CONGESTED", "FAILURE"])

        # Test Live Packets API
        url_packets = reverse("dashboard:api_live_packets")
        response = self.client.get(url_packets)
        self.assertEqual(response.status_code, 200)
        pkts_data = response.json()
        self.assertIn("packets", pkts_data)
        self.assertIsInstance(pkts_data["packets"], list)

    def test_reports_with_data(self):
        """Verifies the reports page can generate telemetry charts."""
        # Seed a couple of metrics/state rows so the plots are generated
        db_manager.save_metric(0.0, 0.0, 0.0, 0.0, 0.0, 0.0)
        db_manager.save_state_history(0.0, "NORMAL", 0.0, 0.0, 0.0)

        url_reports = reverse("dashboard:reports")
        response = self.client.get(url_reports)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/png;base64", count=None, status_code=200)
