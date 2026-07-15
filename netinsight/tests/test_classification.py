import os
import shutil
import tempfile
import unittest
from pathlib import Path

from netinsight.classification.classifier import TrafficClassifier
from netinsight.classification.train import train_and_save_model
from netinsight.config import settings


class TestTrafficClassification(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._orig_svm_path = settings.SVM_MODEL_PATH
        cls.test_model_dir = tempfile.mkdtemp()
        settings.SVM_MODEL_PATH = str(Path(cls.test_model_dir) / "svm_model.joblib")
        os.environ["NETINSIGHT_SVM_PATH"] = settings.SVM_MODEL_PATH

        # Run SVM model training pipeline on setup (this creates svm_model.joblib and scaler.joblib)
        cls.train_results = train_and_save_model()

    @classmethod
    def tearDownClass(cls):
        settings.SVM_MODEL_PATH = cls._orig_svm_path
        shutil.rmtree(cls.test_model_dir, ignore_errors=True)

    def setUp(self):
        self.classifier = TrafficClassifier()

    def test_svm_training_metrics(self):
        """Verifies SVM trains successfully, produces joblib files, and prints evaluation metrics."""
        self.assertIsNotNone(self.train_results)
        self.assertGreaterEqual(self.train_results["accuracy"], 0.80) # synthetic classification is highly separable

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

        # Verify confusion matrix dimensions (4x4)
        cm = self.train_results["confusion_matrix"]
        self.assertEqual(len(cm), 4)
        self.assertEqual(len(cm[0]), 4)

        # Verify target metrics precision, recall, F1
        report = self.train_results["report"]
        self.assertIn("accuracy", report)
        self.assertIn("Web Browsing", report)
        self.assertIn("Streaming", report)
        self.assertIn("File Transfer", report)
        self.assertIn("Potentially Suspicious", report)

    def test_classifier_loading_and_inference(self):
        """Verifies TrafficClassifier successfully loads joblib files and performs predictions."""
        self.assertTrue(self.classifier.load_model())
        self.assertIsNotNone(self.classifier.clf)
        self.assertIsNotNone(self.classifier.scaler)

        # Mock a Web Browsing packet
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
        self.assertIn(res_web, ["Web Browsing", "Streaming", "File Transfer", "Potentially Suspicious"])

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

    def test_heuristic_fallback(self):
        """Verifies rule-based classification fallback functions correctly when models are deleted."""
        # Unload classifier
        self.classifier.clf = None
        self.classifier.scaler = None

        # Test suspicious heuristic: high rates
        pkt_attack = {
            "src_ip": "192.168.1.66",
            "dst_ip": "10.0.0.9",
            "size": 64,
            "protocol": "TCP",
            "timestamp": 30000.0,
            "latency_est": 0.450, # High latency spike
            "dst_port": 445
        }
        res_attack = self.classifier.classify_packet(pkt_attack)
        self.assertEqual(res_attack, "Potentially Suspicious")

        # Test File Transfer heuristic: port 21 (FTP)
        pkt_ftp = {
            "src_ip": "192.168.1.66",
            "dst_ip": "10.0.0.9",
            "size": 1400,
            "protocol": "TCP",
            "timestamp": 30005.0,
            "latency_est": 0.030,
            "dst_port": 21
        }
        res_ftp = self.classifier.classify_packet(pkt_ftp)
        self.assertEqual(res_ftp, "File Transfer")

if __name__ == "__main__":
    unittest.main()
