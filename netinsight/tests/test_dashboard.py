import os
import shutil
import tempfile
import time
from pathlib import Path

from django.test import Client, TestCase, TransactionTestCase
from django.urls import reverse

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netinsight.config.settings")

import django

django.setup()

from netinsight.config import settings
from netinsight.dashboard.models import Agent, MetricRecord, StateHistory
from netinsight.database import db_manager


class TestDashboardViews(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig_db_path = settings.DB_PATH
        cls.test_db_dir = tempfile.mkdtemp()
        settings.DB_PATH = str(Path(cls.test_db_dir) / "test_netinsight_dashboard.db")
        os.environ["NETINSIGHT_DB_PATH"] = settings.DB_PATH
        db_manager.init_db()
        db_manager.clear_db()
        cls.client = Client()

    @classmethod
    def tearDownClass(cls):
        db_manager.clear_db()
        settings.DB_PATH = cls._orig_db_path
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
        # Create an active agent so the metrics logic runs
        from django.utils import timezone
        Agent.objects.create(mac_address="00:11:22:33:44:55", hostname="Agent 1", ip_address="192.168.1.5", last_seen=timezone.now())

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
        self.assertIn(data["network_state"], ["Normal", "Busy", "Congested", "Under Attack", "Recovering"])

        # Test Live Packets API
        url_packets = reverse("dashboard:api_live_packets")
        response = self.client.get(url_packets)
        self.assertEqual(response.status_code, 200)
        pkts_data = response.json()
        self.assertIn("packets", pkts_data)
        self.assertIsInstance(pkts_data["packets"], list)

    def test_reports_with_data(self):
        """Verifies the reports page can generate telemetry charts."""
        # Seed a couple of metrics/state rows via Django ORM so the plots are generated
        MetricRecord.objects.create(timestamp=time.time() - 10, throughput=1.0, packet_rate=1.0, bandwidth_util=1.0, latency=0.015, packet_loss=0.0)
        MetricRecord.objects.create(timestamp=time.time() - 5, throughput=2.0, packet_rate=2.0, bandwidth_util=2.0, latency=0.015, packet_loss=0.0)
        MetricRecord.objects.create(timestamp=time.time(), throughput=3.0, packet_rate=3.0, bandwidth_util=3.0, latency=0.015, packet_loss=0.0)
        StateHistory.objects.create(timestamp=time.time(), network_state="Normal", bandwidth_utilization=1.0, packet_loss=0.0, latency=0.015)

        url_reports = reverse("dashboard:reports")
        response = self.client.get(url_reports)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "data:image/png;base64", count=None, status_code=200)

    def test_optimization_post_validation(self):
        """Verifies optimization POST handling validates list length and clamping boundaries."""
        url = reverse("dashboard:optimization")
        # Valid POST
        valid_payload = {
            "priorities": ["1.0", "2.0", "0.5", "3.0"],
            "min_bounds": ["5", "15", "2", "10"],
            "max_bounds": ["40", "60", "30", "50"],
            "capacity": "100"
        }
        response = self.client.post(url, valid_payload)
        self.assertEqual(response.status_code, 200)

        # Malformed POST (fewer than 4 classes) - should be handled gracefully without IndexError
        malformed_payload = {
            "priorities": ["1.0", "2.0"],
            "min_bounds": ["5"],
            "max_bounds": ["40"],
            "capacity": "100"
        }
        response = self.client.post(url, malformed_payload)
        self.assertEqual(response.status_code, 200)

    def test_shared_classifier_singleton(self):
        """Verifies that get_shared_classifier returns a shared singleton instance."""
        from netinsight.classification.classifier import get_shared_classifier
        clf1 = get_shared_classifier()
        clf2 = get_shared_classifier()
        self.assertIs(clf1, clf2, "get_shared_classifier must return the exact same instance")

    def test_bulk_packet_preparation(self):
        """Verifies that prepare_packet_record builds unsaved PacketRecord instances for batch insert."""
        from django.utils import timezone

        from netinsight.analytics.flow_builder import prepare_packet_record
        from netinsight.dashboard.models import PacketRecord
        agent = Agent.objects.create(mac_address="00:aa:bb:cc:dd:ee", hostname="Agent Bulk", ip_address="192.168.1.10", last_seen=timezone.now())
        pkt_dict = {
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 12345,
            "dst_port": 80,
            "protocol": "TCP",
            "size": 512,
            "timestamp": time.time(),
            "ttl": 64
        }
        record = prepare_packet_record(agent, pkt_dict)
        self.assertIsInstance(record, PacketRecord)
        self.assertIsNone(record.pk, "Prepared record should be unsaved for bulk_create")
        self.assertEqual(record.agent, agent)

    def test_agent_token_validation(self):
        """Verifies _validate_agent_token returns False when X-Agent-Token is mismatched or missing."""
        from django.test import RequestFactory

        from netinsight.dashboard.views import _validate_agent_token

        factory = RequestFactory()

        original_token = getattr(settings, "NETINSIGHT_AGENT_TOKEN", None)
        original_debug = settings.DEBUG

        try:
            settings.NETINSIGHT_AGENT_TOKEN = "secret_token"
            settings.DEBUG = False

            # Test when token is missing
            request = factory.post("/api/v1/agents/")
            self.assertFalse(_validate_agent_token(request))

            # Test when token is mismatched
            request = factory.post("/api/v1/agents/", HTTP_X_AGENT_TOKEN="wrong_token")
            self.assertFalse(_validate_agent_token(request))

            # Test when token matches
            request = factory.post("/api/v1/agents/", HTTP_X_AGENT_TOKEN="secret_token")
            self.assertTrue(_validate_agent_token(request))
        finally:
            settings.NETINSIGHT_AGENT_TOKEN = original_token
            settings.DEBUG = original_debug

    def test_xss_escaping_in_agent_registration(self):
        """Verifies malicious XSS scripts in agent hostname/metadata are HTML escaped."""
        xss_payload = {
            "mac_address": "00:11:22:33:44:55",
            "hostname": "<script>alert('xss')</script>",
            "device_type": "<b onmouseover=alert(1)>Generic</b>",
            "vendor": "Generic <iframe src=evil.com></iframe>",
            "ip_address": "192.168.1.10"
        }
        res = self.client.post("/api/v1/agents/register", data=xss_payload, content_type="application/json")
        self.assertEqual(res.status_code, 200)

        agent = Agent.objects.get(mac_address="00:11:22:33:44:55")
        self.assertNotIn("<script>", agent.hostname)
        self.assertIn("&lt;script&gt;", agent.hostname)
        self.assertNotIn("<b onmouseover", agent.device_type)

class TestConcurrency(TransactionTestCase):

    def test_concurrent_telemetry_write_safety(self):
        """Verifies concurrent multi-threaded telemetry writes execute safely without DB lock exceptions."""
        from concurrent.futures import ThreadPoolExecutor

        agents = [
            Agent.objects.create(
                mac_address=f"00:AA:BB:CC:DD:{idx:02X}",
                hostname=f"Thread-Host-{idx}",
                device_type="Server",
                ip_address=f"192.168.1.{10+idx}"
            ) for idx in range(5)
        ]

        def send_telemetry(idx):
            ag = agents[idx]
            payload = {
                "agent_id": str(ag.id),
                "stats": {
                    "cpu_usage": 15.0,
                    "memory_usage": 40.0,
                    "disk_usage": 20.0,
                    "active_connections": 5,
                    "bytes_sent": 1000,
                    "bytes_recv": 2000,
                },
                "packets": [
                    {
                        "src_ip": f"192.168.1.{idx+1}",
                        "dst_ip": "10.0.0.1",
                        "src_port": 1234,
                        "dst_port": 80,
                        "protocol": "TCP",
                        "size": 512,
                        "timestamp": time.time()
                    }
                ]
            }
            client = Client()
            return client.post("/api/v1/agents/telemetry", data=payload, content_type="application/json")

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_telemetry, i) for i in range(5)]
            results = [f.result() for f in futures]

        for res in results:
            self.assertEqual(res.status_code, 200)

