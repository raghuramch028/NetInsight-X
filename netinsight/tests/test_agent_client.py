"""Regression tests for the Python edge agent's HTTP client (agent/sender.py).

Verifies the X-Agent-Token header is actually attached to outbound requests when configured
(previously it was never sent regardless of NETINSIGHT_AGENT_TOKEN configuration).
"""
import importlib
import os
import unittest
from unittest.mock import MagicMock, patch


class TestPythonAgentAuthHeaders(unittest.TestCase):

    def tearDown(self):
        os.environ.pop("NETINSIGHT_AGENT_TOKEN", None)
        self._reload_agent_modules()

    def _reload_agent_modules(self):
        """Re-imports agent.config (and agent.sender, which reads it) so each test observes
        the env var state it set, independent of import order across the test run."""
        from agent import config as agent_config
        importlib.reload(agent_config)
        from agent import sender as agent_sender
        importlib.reload(agent_sender)
        return agent_sender

    def test_register_sends_token_header_when_configured(self):
        os.environ["NETINSIGHT_AGENT_TOKEN"] = "test-secret-token"
        agent_sender_mod = self._reload_agent_modules()
        sender = agent_sender_mod.TelemetrySender()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"agent_id": "abc-123"}

        with patch.object(agent_sender_mod, "requests") as mock_requests, \
             patch.object(sender, "save_agent_id"):
            mock_requests.post.return_value = mock_response
            sender.register("00:11:22:33:44:55", "test-host", "TestOS", "TestVendor")

        _, kwargs = mock_requests.post.call_args
        self.assertEqual(kwargs["headers"].get("X-Agent-Token"), "test-secret-token")

    def test_register_sends_no_token_header_when_unconfigured(self):
        os.environ.pop("NETINSIGHT_AGENT_TOKEN", None)
        agent_sender_mod = self._reload_agent_modules()
        sender = agent_sender_mod.TelemetrySender()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"agent_id": "abc-123"}

        with patch.object(agent_sender_mod, "requests") as mock_requests, \
             patch.object(sender, "save_agent_id"):
            mock_requests.post.return_value = mock_response
            sender.register("00:11:22:33:44:55", "test-host", "TestOS", "TestVendor")

        _, kwargs = mock_requests.post.call_args
        self.assertEqual(kwargs["headers"], {})

    def test_send_telemetry_sends_token_header_when_configured(self):
        os.environ["NETINSIGHT_AGENT_TOKEN"] = "test-secret-token"
        agent_sender_mod = self._reload_agent_modules()
        sender = agent_sender_mod.TelemetrySender()
        sender.agent_id = "existing-agent-id"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"enforced_qos": {}}

        with patch.object(agent_sender_mod, "requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            sender.send_telemetry({"cpu_usage": 1.0}, [])

        _, kwargs = mock_requests.post.call_args
        self.assertEqual(kwargs["headers"].get("X-Agent-Token"), "test-secret-token")

    def test_send_telemetry_records_rtt_for_next_cycle(self):
        """Regression (Phase 2): latency was hardcoded server-side; the agent must measure and
        expose the round-trip time of its own telemetry POST so it can be reported next cycle."""
        agent_sender_mod = self._reload_agent_modules()
        sender = agent_sender_mod.TelemetrySender()
        sender.agent_id = "existing-agent-id"
        self.assertIsNone(sender.last_rtt_seconds)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"enforced_qos": {}}

        with patch.object(agent_sender_mod, "requests") as mock_requests:
            mock_requests.post.return_value = mock_response
            sender.send_telemetry({"cpu_usage": 1.0}, [])

        self.assertIsNotNone(sender.last_rtt_seconds)
        self.assertGreaterEqual(sender.last_rtt_seconds, 0.0)


class TestPythonAgentServerFlag(unittest.TestCase):
    """Regression (Phase 7): the README documents `python main.py --server <url>` for the
    Python agent, but main.py never parsed any CLI arguments — the flag was silently ignored
    (same class of bug independently found and fixed for the Go agent's -server flag)."""

    def tearDown(self):
        from agent import config as agent_config
        importlib.reload(agent_config)

    def test_set_server_url_updates_derived_endpoints(self):
        from agent import config as agent_config
        agent_config.set_server_url("http://192.168.1.50:9000")

        self.assertEqual(agent_config.SERVER_URL, "http://192.168.1.50:9000")
        self.assertEqual(agent_config.REGISTRATION_ENDPOINT, "http://192.168.1.50:9000/api/v1/agents/register")
        self.assertEqual(agent_config.TELEMETRY_ENDPOINT, "http://192.168.1.50:9000/api/v1/agents/telemetry")


if __name__ == "__main__":
    unittest.main()
