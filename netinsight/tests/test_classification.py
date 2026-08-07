import unittest

from django.test import TestCase

from netinsight.classification.classifier import TrafficClassifier
from netinsight.classification.llm_classifier import LLMClassifier
from netinsight.config import settings


class TestTrafficClassification(TestCase):

    def setUp(self):
        self.classifier = TrafficClassifier()

    def test_nvidia_deepseek_settings(self):
        """Verifies NVIDIA DeepSeek API key and model settings exist."""
        self.assertIsInstance(settings.NVIDIA_API_KEY, str)
        self.assertEqual(settings.NVIDIA_MODEL_NAME, "deepseek-ai/deepseek-r1")

    def test_llm_classifier_initialization(self):
        """Verifies LLMClassifier initializes with NVIDIA DeepSeek API settings."""
        llm = LLMClassifier()
        self.assertEqual(llm.nvidia_api_key, settings.NVIDIA_API_KEY)
        self.assertEqual(llm.nvidia_model_name, settings.NVIDIA_MODEL_NAME)

    def test_classifier_loading_and_inference(self):
        """Verifies TrafficClassifier performs packet classification."""
        self.assertIsNotNone(self.classifier)

        # Mock a Normal Web Browsing packet
        pkt_web = {
            "src_ip": "192.168.1.5",
            "dst_ip": "8.8.8.8",
            "size": 500,
            "protocol": "TCP",
            "timestamp": 20000.0,
            "latency_est": 0.010,
            "dst_port": 80
        }
        res_web = self.classifier.classify_packet(pkt_web)
        # Check that classification returns a valid category name
        self.assertIn(res_web, ["Normal", "DoS", "DDoS", "Brute Force", "Reconnaissance", "Mirai", "Other Attacks"])

    def test_rolling_ip_cache_feature_extraction(self):
        """Tests that the sliding window cache accumulates connections and rates correctly."""
        src = "192.168.1.99"

        # Simulate sending 5 packets to 3 unique destination IPs within 3 seconds
        rate, freq = self.classifier.update_ip_cache(src, "10.0.0.1", 1000, 10000.0)
        rate, freq = self.classifier.update_ip_cache(src, "10.0.0.1", 1000, 10001.0)
        rate, freq = self.classifier.update_ip_cache(src, "10.0.0.2", 1000, 10002.0)
        rate, freq = self.classifier.update_ip_cache(src, "10.0.0.3", 1000, 10002.5)
        rate, freq = self.classifier.update_ip_cache(src, "10.0.0.3", 1000, 10003.0)

        # Rate: 5 packets over 10 second window = 0.5 pkts/sec
        self.assertAlmostEqual(rate, 0.5, places=2)
        # Freq: 3 unique destinations (10.0.0.1, 10.0.0.2, 10.0.0.3)
        self.assertEqual(freq, 3.0)

    def test_heuristic_fallback_rules(self):
        """Verifies rule-based classification fallback functions correctly when models are bypassed."""
        # Unload machine learning model to force heuristic execution
        self.classifier.clf = None
        self.classifier.scaler = None

        # Test DDoS rule: high packet rate (>1000 pps), small size (<200 bytes)
        pkt_ddos = {
            "src_ip": "192.168.1.66",
            "dst_ip": "10.0.0.9",
            "size": 64,
            "protocol": "TCP",
            "timestamp": 30000.0,
            "packet_rate": 1500.0,
            "conn_frequency": 5.0
        }
        self.assertEqual(self.classifier.classify_packet(pkt_ddos), "DDoS")

        # Test DoS rule: high packet rate (>500 pps), larger size
        pkt_dos = {
            "src_ip": "192.168.1.66",
            "dst_ip": "10.0.0.9",
            "size": 500,
            "protocol": "TCP",
            "timestamp": 30000.0,
            "packet_rate": 600.0,
            "conn_frequency": 5.0
        }
        self.assertEqual(self.classifier.classify_packet(pkt_dos), "DoS")

        # Test Mirai rule: UDP, high packet rate (>300 pps), high connection frequency (>30)
        pkt_mirai = {
            "src_ip": "192.168.1.66",
            "dst_ip": "10.0.0.9",
            "size": 128,
            "protocol": "UDP",
            "timestamp": 30000.0,
            "dst_port": 5004,
            "packet_rate": 400.0,
            "conn_frequency": 35.0
        }
        self.assertEqual(self.classifier.classify_packet(pkt_mirai), "Mirai")

        # Test Brute Force rule: Port 22 (SSH), packet_rate > 50.0
        pkt_brute = {
            "src_ip": "192.168.1.66",
            "dst_ip": "10.0.0.9",
            "size": 256,
            "protocol": "TCP",
            "timestamp": 30000.0,
            "dst_port": 22,
            "packet_rate": 60.0,
            "conn_frequency": 2.0
        }
        self.assertEqual(self.classifier.classify_packet(pkt_brute), "Brute Force")

    def test_llm_classifier_fallback(self):
        """Verifies LLMClassifier returns None when unconfigured and TrafficClassifier falls back
        to the heuristic rules cleanly."""
        from netinsight.classification.llm_classifier import LLMClassifier
        llm = LLMClassifier()
        import pandas as pd
        df = pd.DataFrame([{"size": 64, "protocol": 6, "latency": 0.01, "packet_rate": 10.0, "conn_frequency": 1.0}])
        self.assertIsNone(llm.classify_batch(df))

        # TrafficClassifier fallback mechanism
        pkt_normal = {
            "src_ip": "192.168.1.50",
            "dst_ip": "10.0.0.1",
            "size": 64,
            "protocol": "TCP",
            "timestamp": 1000.0,
            "packet_rate": 2.0,
            "conn_frequency": 1.0
        }
        res = self.classifier.classify_packet(pkt_normal)
        self.assertEqual(res, "Normal")
        self.assertIn(self.classifier.last_engine_used, ["NVIDIA DeepSeek AI", "Heuristics"])

    def test_llm_success_path_returns_string_label_not_dict(self):
        """Regression test: TrafficClassifier.classify_packet() previously returned the raw dict
        from LLMClassifier ({"label":..,"confidence":..,"reasoning":..}) instead of the label
        string, which would corrupt any string consumer (e.g. FlowRecord.threat_label)."""
        from unittest.mock import MagicMock, patch

        clf = TrafficClassifier()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{
                "message": {
                    "content": '{"label": "Normal", "confidence": 0.95, "reasoning": "Standard web traffic"}'
                }
            }]
        }
        mock_response.raise_for_status.return_value = None

        pkt = {
            "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "size": 500, "protocol": "TCP",
            "timestamp": 1000.0, "packet_rate": 2.0, "conn_frequency": 1.0
        }

        with patch.object(clf.llm_classifier, "nvidia_api_key", "fake-key-for-test"), \
             patch("netinsight.classification.llm_classifier.requests.post", return_value=mock_response):
            result = clf.classify_packet(pkt)

        self.assertIsInstance(result, str)
        self.assertEqual(result, "Normal")
        self.assertEqual(clf.last_engine_used, "NVIDIA DeepSeek AI")

    def test_llm_malformed_response_falls_back_to_normal_safely(self):
        """Verifies a malformed LLM response (missing/invalid 'label') never propagates as a
        classification result — it must fail closed to 'Normal', not raise or return garbage."""
        from unittest.mock import MagicMock, patch

        clf = TrafficClassifier()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": '{"confidence": 0.5, "reasoning": "no label field"}'}}]
        }
        mock_response.raise_for_status.return_value = None

        pkt = {
            "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "size": 500, "protocol": "TCP",
            "timestamp": 1000.0, "packet_rate": 2.0, "conn_frequency": 1.0
        }

        with patch.object(clf.llm_classifier, "nvidia_api_key", "fake-key-for-test"), \
             patch("netinsight.classification.llm_classifier.requests.post", return_value=mock_response):
            result = clf.classify_packet(pkt)

        self.assertEqual(result, "Normal")

    def _mock_llm_response(self, label: str, confidence: float):
        from unittest.mock import MagicMock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": f'{{"label": "{label}", "confidence": {confidence}, "reasoning": "test"}}'}}]
        }
        mock_response.raise_for_status.return_value = None
        return mock_response

    def test_low_confidence_llm_threat_is_suppressed_to_normal(self):
        """svm_confidence_threshold (Settings page) previously had no effect on classification —
        it was a persisted value nothing ever read. A non-Normal LLM label below the configured
        threshold must now be suppressed rather than raised as a threat."""
        from unittest.mock import patch

        from netinsight.dashboard.models import SystemSettings
        SystemSettings.objects.create(svm_confidence_threshold=0.80)

        clf = TrafficClassifier()
        pkt = {
            "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "size": 500, "protocol": "TCP",
            "timestamp": 1000.0, "packet_rate": 2.0, "conn_frequency": 1.0
        }
        mock_response = self._mock_llm_response("Reconnaissance", 0.55)  # below 0.80 threshold

        with patch.object(clf.llm_classifier, "nvidia_api_key", "fake-key-for-test"), \
             patch("netinsight.classification.llm_classifier.requests.post", return_value=mock_response):
            result = clf.classify_packet(pkt)

        self.assertEqual(result, "Normal")

    def test_high_confidence_llm_threat_is_reported(self):
        """A non-Normal LLM label at/above the configured threshold must still be reported."""
        from unittest.mock import patch

        from netinsight.dashboard.models import SystemSettings
        SystemSettings.objects.create(svm_confidence_threshold=0.80)

        clf = TrafficClassifier()
        pkt = {
            "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "size": 500, "protocol": "TCP",
            "timestamp": 1000.0, "packet_rate": 2.0, "conn_frequency": 1.0
        }
        mock_response = self._mock_llm_response("Reconnaissance", 0.92)  # above 0.80 threshold

        with patch.object(clf.llm_classifier, "nvidia_api_key", "fake-key-for-test"), \
             patch("netinsight.classification.llm_classifier.requests.post", return_value=mock_response):
            result = clf.classify_packet(pkt)

        self.assertEqual(result, "Reconnaissance")
        self.assertEqual(clf.last_llm_confidence, 0.92)

    def test_missing_settings_row_uses_default_threshold(self):
        """When no SystemSettings row exists yet, the classifier must fall back to a sane
        default threshold rather than erroring or treating every LLM call as unconditionally
        trusted."""
        from unittest.mock import patch

        from netinsight.dashboard.models import SystemSettings
        self.assertFalse(SystemSettings.objects.exists())

        clf = TrafficClassifier()
        pkt = {
            "src_ip": "192.168.1.5", "dst_ip": "8.8.8.8", "size": 500, "protocol": "TCP",
            "timestamp": 1000.0, "packet_rate": 2.0, "conn_frequency": 1.0
        }
        mock_response = self._mock_llm_response("DoS", 0.50)  # below the 0.80 default

        with patch.object(clf.llm_classifier, "nvidia_api_key", "fake-key-for-test"), \
             patch("netinsight.classification.llm_classifier.requests.post", return_value=mock_response):
            result = clf.classify_packet(pkt)

        self.assertEqual(result, "Normal")


if __name__ == "__main__":
    unittest.main()
