import os
import shutil
import tempfile
import unittest
from pathlib import Path

from django.test import TestCase

from netinsight.classification.classifier import TrafficClassifier
from netinsight.classification.train import train_and_save_model
from netinsight.config import settings


class TestTrafficClassification(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._orig_svm_path = settings.SVM_MODEL_PATH
        cls.test_model_dir = tempfile.mkdtemp()
        settings.SVM_MODEL_PATH = str(Path(cls.test_model_dir) / "svm_model.joblib")
        os.environ["NETINSIGHT_SVM_PATH"] = settings.SVM_MODEL_PATH

        # Run SVM model training pipeline on setup (creates svm_model.joblib, scaler.joblib, metrics json)
        cls.train_results = train_and_save_model()

    @classmethod
    def tearDownClass(cls):
        settings.SVM_MODEL_PATH = cls._orig_svm_path
        shutil.rmtree(cls.test_model_dir, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.classifier = TrafficClassifier()

    def test_svm_training_metrics(self):
        """Verifies SVM trains successfully, produces joblib files, and prints evaluation metrics."""
        self.assertIsNotNone(self.train_results)
        self.assertGreaterEqual(self.train_results["accuracy"], 0.50)

        # Verify model files are written on disk
        self.assertTrue(Path(settings.SVM_MODEL_PATH).exists())
        self.assertTrue((Path(settings.SVM_MODEL_PATH).parent / "scaler.joblib").exists())
        self.assertTrue((Path(settings.SVM_MODEL_PATH).parent / "svm_model_metrics.json").exists())

        # Verify real metrics are persisted and loadable
        stats = self.classifier.get_model_stats()
        self.assertIsNotNone(stats.get("accuracy"))
        self.assertIsNotNone(stats.get("precision"))
        self.assertIsNotNone(stats.get("recall"))
        self.assertIsNotNone(stats.get("f1_score"))
        self.assertIn("kernel", stats)
        self.assertIn("features", stats)

        # Verify confusion matrix dimensions (7x7 classes)
        cm = self.train_results["confusion_matrix"]
        self.assertEqual(len(cm), 7)
        self.assertEqual(len(cm[0]), 7)

        # Verify target metrics precision, recall, F1 keys
        report = self.train_results["report"]
        self.assertIn("accuracy", report)
        self.assertIn("Normal", report)
        self.assertIn("DoS", report)
        self.assertIn("DDoS", report)
        self.assertIn("Mirai", report)

    def test_classifier_loading_and_inference(self):
        """Verifies TrafficClassifier successfully loads joblib files and performs predictions."""
        self.assertTrue(self.classifier.load_model())
        self.assertIsNotNone(self.classifier.clf)
        self.assertIsNotNone(self.classifier.scaler)

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
        """Verifies LLMClassifier returns None when unconfigured and falls back to XGBoost cleanly."""
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
        self.assertEqual(self.classifier.last_engine_used, "XGBoost")


if __name__ == "__main__":
    unittest.main()
