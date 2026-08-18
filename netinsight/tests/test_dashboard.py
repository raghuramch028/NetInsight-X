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
from netinsight.dashboard.models import Agent
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
            ("dashboard:optimization", {}),
            ("dashboard:classification", {}),
        ]

        for view_name, kwargs in views_to_test:
            url = reverse(view_name, kwargs=kwargs)
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, f"Failed rendering view {view_name} at URL {url}")

    def test_health_check_endpoint(self):
        """The /healthz endpoint must be reachable without any authentication."""
        response = self.client.get(reverse("dashboard:api_health_check"))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertTrue(data["database"])

    def test_health_check_ignores_dashboard_auth_gate(self):
        original = getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False)
        try:
            settings.NETINSIGHT_REQUIRE_AUTH = True
            response = self.client.get(reverse("dashboard:api_health_check"))
            self.assertEqual(response.status_code, 200)
        finally:
            settings.NETINSIGHT_REQUIRE_AUTH = original

    def test_json_api_endpoints(self):
        """Verifies the JSON APIs for Chart.js and packet logs return expected structures."""
        from django.utils import timezone
        Agent.objects.create(mac_address="00:11:22:33:44:55", hostname="Agent 1", ip_address="192.168.1.5", last_seen=timezone.now())

        url_metrics = reverse("dashboard:api_live_metrics")
        response = self.client.get(url_metrics)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertIn("throughput", data)
        self.assertIn("packet_rate", data)
        self.assertIn("bandwidth_util", data)
        self.assertIn("latency", data)
        self.assertIn("packet_loss", data)
        self.assertIsInstance(data["bandwidth_util"], (int, float))

        url_packets = reverse("dashboard:api_live_packets")
        response = self.client.get(url_packets)
        self.assertEqual(response.status_code, 200)
        pkts_data = response.json()
        self.assertIn("packets", pkts_data)
        self.assertIsInstance(pkts_data["packets"], list)

    def test_optimization_post_validation(self):
        """Verifies optimization POST handling validates list length and clamping boundaries."""
        url = reverse("dashboard:optimization")
        valid_payload = {
            "priorities": ["1.0", "2.0", "0.5", "3.0"],
            "min_bounds": ["5", "15", "2", "10"],
            "max_bounds": ["40", "60", "30", "50"],
            "capacity": "100"
        }
        response = self.client.post(url, valid_payload)
        self.assertEqual(response.status_code, 200)

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

            request = factory.post("/api/v1/agents/")
            self.assertFalse(_validate_agent_token(request))

            request = factory.post("/api/v1/agents/", HTTP_X_AGENT_TOKEN="wrong_token")
            self.assertFalse(_validate_agent_token(request))

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

    def test_register_agent_rejects_invalid_mac_address(self):
        res = self.client.post(
            "/api/v1/agents/register",
            data={"mac_address": "not-a-mac-address", "hostname": "Bad-Mac-Host"},
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 400)
        self.assertFalse(Agent.objects.filter(hostname="Bad-Mac-Host").exists())

    def test_register_agent_falls_back_on_invalid_ip(self):
        res = self.client.post(
            "/api/v1/agents/register",
            data={
                "mac_address": "00:11:22:33:44:cc",
                "hostname": "Bad-IP-Host",
                "ip_address": "'; DROP TABLE agents; --",
            },
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        agent = Agent.objects.get(mac_address="00:11:22:33:44:cc")
        self.assertEqual(agent.ip_address, "0.0.0.0")

    def test_register_agent_truncates_overlong_fields(self):
        res = self.client.post(
            "/api/v1/agents/register",
            data={
                "mac_address": "00:11:22:33:44:dd",
                "hostname": "H" * 500,
                "device_type": "D" * 500,
                "vendor": "V" * 500,
            },
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        agent = Agent.objects.get(mac_address="00:11:22:33:44:dd")
        self.assertLessEqual(len(agent.hostname), 255)
        self.assertLessEqual(len(agent.device_type), 100)
        self.assertLessEqual(len(agent.vendor), 255)

    def test_register_agent_error_response_does_not_leak_exception_text(self):
        from unittest.mock import patch

        with patch(
            "netinsight.dashboard.views.api_views.Agent.objects.get_or_create",
            side_effect=RuntimeError("super secret internal detail"),
        ):
            res = self.client.post(
                "/api/v1/agents/register",
                data={"mac_address": "00:11:22:33:44:ee", "hostname": "Err-Host"},
                content_type="application/json",
            )
        self.assertEqual(res.status_code, 500)
        self.assertNotIn("super secret internal detail", res.json().get("error", ""))

    def test_dashboard_auth_gate_blocks_when_required(self):
        original = getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False)
        try:
            settings.NETINSIGHT_REQUIRE_AUTH = True

            page_response = self.client.get(reverse("dashboard:index"))
            self.assertEqual(page_response.status_code, 401)

            api_response = self.client.get(reverse("dashboard:api_live_metrics"))
            self.assertEqual(api_response.status_code, 401)
        finally:
            settings.NETINSIGHT_REQUIRE_AUTH = original

    def test_dashboard_open_when_auth_not_required(self):
        original = getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False)
        try:
            settings.NETINSIGHT_REQUIRE_AUTH = False
            response = self.client.get(reverse("dashboard:index"))
            self.assertEqual(response.status_code, 200)
        finally:
            settings.NETINSIGHT_REQUIRE_AUTH = original

    def test_agent_ingestion_endpoints_unaffected_by_dashboard_auth_gate(self):
        original = getattr(settings, "NETINSIGHT_REQUIRE_AUTH", False)
        try:
            settings.NETINSIGHT_REQUIRE_AUTH = True
            res = self.client.post(
                "/api/v1/agents/register",
                data={"mac_address": "00:aa:bb:cc:dd:99", "hostname": "Gate-Test"},
                content_type="application/json",
            )
            self.assertEqual(res.status_code, 200)
        finally:
            settings.NETINSIGHT_REQUIRE_AUTH = original


class TestConcurrency(TransactionTestCase):

    def test_concurrent_telemetry_write_safety(self):
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

        from netinsight.analytics.telemetry_handler import drain_telemetry_pool
        drain_telemetry_pool(timeout=5.0)

        for res in results:
            self.assertEqual(res.status_code, 200)
