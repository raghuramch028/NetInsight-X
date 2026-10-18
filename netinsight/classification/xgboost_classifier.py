"""Custom XGBoost Threat Classifier module for NetInsight-X.

Loads trained XGBoost model (.joblib) and scaler (.joblib) to perform
sub-millisecond (< 1ms) local threat classification and anomaly detection.
"""
import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np

logger = logging.getLogger("netinsight.classification")

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "xgboost_threat_model.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"

CLASS_MAP = {
    0: "Normal",
    1: "DoS / DDoS",
    2: "Mirai Botnet",
    3: "Reconnaissance",
    4: "Brute Force"
}

PROTOCOL_NUM_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "6": 6,
    "17": 17,
}

class XGBoostTrafficClassifier:
    """Sub-millisecond local XGBoost Classifier trained on CICIoT2023 / UNSW-NB15 features."""

    def __init__(self):
        self.model = None
        self.scaler = None
        self.metrics = {}
        self.is_loaded = False
        self.load_model()

    def load_model(self) -> bool:
        """Loads trained XGBoost model weights and scaler from disk."""
        try:
            if MODEL_PATH.exists() and SCALER_PATH.exists():
                self.model = joblib.load(MODEL_PATH)
                self.scaler = joblib.load(SCALER_PATH)
                if METRICS_PATH.exists():
                    with open(METRICS_PATH, encoding="utf-8") as f:
                        self.metrics = json.load(f)
                self.is_loaded = True
                logger.info(f"[XGBoost Classifier] Successfully loaded trained ML model from {MODEL_PATH}")
                return True
        except Exception as e:
            logger.error(f"[XGBoost Classifier] Failed to load trained XGBoost model: {e}")
        self.is_loaded = False
        return False

    def classify_packet(self, packet_dict: dict) -> dict | None:
        """Performs sub-millisecond threat prediction on network flow features.

        Returns:
            dict: {"label": str, "confidence": float, "latency_ms": float, "reasoning": str}
        """
        if not self.is_loaded:
            if not self.load_model():
                return None

        start_time = time.perf_counter()
        try:
            pkt_size = float(packet_dict.get("size", 500))        # AVG: packet/flow avg size
            pkt_rate = float(packet_dict.get("packet_rate", 15))   # Rate: packets per second

            # Header_Length in CICIoT2023 = cumulative header bytes across all packets in the flow
            # Per-packet header: TCP = 40 bytes (20 IP + 20 TCP), UDP = 28, other = 20
            proto_raw = str(packet_dict.get("protocol", "TCP")).upper()
            if proto_raw in ("TCP", "6"):
                per_pkt_header = 40.0
            elif proto_raw in ("UDP", "17"):
                per_pkt_header = 28.0
            else:
                per_pkt_header = 20.0
            pkt_count = float(packet_dict.get("packet_count", 1))
            header_length = per_pkt_header * pkt_count  # Cumulative header bytes

            # Number in CICIoT2023 has mean ~9.5, std ~0.8 — it's a derived feature
            # Clamp to realistic range that the scaler was trained on
            number_feature = min(max(pkt_count, 1.0), 20.0)

            proto = float(PROTOCOL_NUM_MAP.get(proto_raw, 6))      # Protocol Type

            features = np.array([[pkt_size, pkt_rate, header_length, number_feature, proto]])
            features_scaled = self.scaler.transform(features)

            probs = self.model.predict_proba(features_scaled)[0]
            class_idx = int(np.argmax(probs))
            confidence = float(probs[class_idx])

            label = CLASS_MAP.get(class_idx, "Normal")
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            reasoning = f"XGBoost trees classified flow as {label} with {confidence*100:.1f}% confidence ({latency_ms:.2f}ms latency)."

            return {
                "label": label,
                "confidence": confidence,
                "latency_ms": latency_ms,
                "reasoning": reasoning
            }
        except Exception as e:
            logger.error(f"[XGBoost Classifier] Prediction error: {e}", exc_info=True)
            return None
