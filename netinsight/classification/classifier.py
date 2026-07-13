import os
import time
import joblib
import logging
import threading
import numpy as np
from pathlib import Path
from netinsight.config import settings

logger = logging.getLogger(__name__)

# Class labels
CLASS_LABELS = {
    0: "Web Browsing",
    1: "Streaming",
    2: "File Transfer",
    3: "Potentially Suspicious"
}

class TrafficClassifier:
    """Classifies network packets using a trained RBF Support Vector Machine.
    
    If the model is missing, falls back to a rule-based heuristic.
    """
    
    def __init__(self):
        self.model_path = Path(settings.SVM_MODEL_PATH)
        self.scaler_path = self.model_path.parent / "scaler.joblib"
        
        self.clf = None
        self.scaler = None
        self.load_model()
        
        # State cache for live feature extraction:
        # Maps src_ip -> list of (timestamp, dst_ip, size) for the last 10 seconds
        self.ip_history = {}
        self.cache_lock = threading.Lock()
        self.window_duration = 10.0 # 10-second history window

    def load_model(self) -> bool:
        """Attempts to load the SVM model and scaler from joblib files.
        
        Returns:
            bool: True if loaded successfully, False if missing.
        """
        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.clf = joblib.load(str(self.model_path))
                self.scaler = joblib.load(str(self.scaler_path))
                logger.info("Successfully loaded SVM classifier and scaler.")
                return True
            except Exception as e:
                logger.error(f"Error loading SVM models: {e}", exc_info=True)
                
        logger.warning("SVM model or scaler not found on disk. Falling back to heuristic classifier.")
        self.clf = None
        self.scaler = None
        return False

    def update_ip_cache(self, src_ip: str, dst_ip: str, size: int, timestamp: float) -> tuple[float, float]:
        """Updates the state cache for the source IP and computes packet rate and connection frequency.
        
        Returns:
            tuple: (packet_rate, connection_frequency) over the sliding window.
        """
        with self.cache_lock:
            now = timestamp
            cutoff = now - self.window_duration
            
            if src_ip not in self.ip_history:
                self.ip_history[src_ip] = []
                
            # Add current packet record
            self.ip_history[src_ip].append((now, dst_ip, size))
            
            # Prune records older than cutoff window
            self.ip_history[src_ip] = [item for item in self.ip_history[src_ip] if item[0] >= cutoff]
            
            # Calculate features
            history = self.ip_history[src_ip]
            packet_count = len(history)
            packet_rate = packet_count / self.window_duration
            
            unique_dests = len(set(item[1] for item in history))
            conn_frequency = float(unique_dests)
            
            # Prevent potential memory leaks by limiting cache size
            if len(self.ip_history) > 1000:
                # Remove inactive IPs
                inactive_ips = [ip for ip, hist in self.ip_history.items() if not hist or hist[-1][0] < cutoff]
                for ip in inactive_ips:
                    del self.ip_history[ip]
                    
            return float(packet_rate), float(conn_frequency)

    def classify_packet(self, packet_dict: dict) -> str:
        """Performs classification on a captured packet dictionary.
        
        Uses SVM model inference when available, falling back to rule-based heuristics.
        """
        src_ip = packet_dict["src_ip"]
        dst_ip = packet_dict["dst_ip"]
        size = packet_dict["size"]
        timestamp = packet_dict["timestamp"]
        proto_str = packet_dict["protocol"]
        
        # Numeric protocol mapping
        proto_map = {"TCP": 6.0, "UDP": 17.0, "ICMP": 1.0}
        protocol = proto_map.get(proto_str.upper(), 0.0)
        
        # Latency
        latency = packet_dict.get("latency_est", None)
        if latency is None:
            latency = 0.015  # Fallback base delay (15ms)

        # Update cache and retrieve engineered features
        packet_rate, conn_frequency = self.update_ip_cache(src_ip, dst_ip, size, timestamp)
        
        # If SVM model is loaded, perform machine learning inference
        if self.clf is not None and self.scaler is not None:
            try:
                feature_vector = np.array([[float(size), float(protocol), float(latency), packet_rate, conn_frequency]])
                scaled_vector = self.scaler.transform(feature_vector)
                prediction = int(self.clf.predict(scaled_vector)[0])
                return CLASS_LABELS.get(prediction, "Web Browsing")
            except Exception as e:
                logger.error(f"Inference error in SVM classifier: {e}. Falling back to heuristics.", exc_info=True)
                
        # --- Rule-Based Heuristic Fallback ---
        # Highly accurate rule-based classification based on sizes, protocols, and ports
        dst_port = packet_dict.get("dst_port", 0)
        src_port = packet_dict.get("src_port", 0)
        
        # 1. Suspicious indicators: massive scan rates or known attack protocols/ports
        if packet_rate > 100.0 or conn_frequency > 30.0 or latency > 0.300:
            return "Potentially Suspicious"
            
        # 2. File Transfer indicators: FTP ports or massive packets with TCP protocol
        if dst_port in [20, 21, 22] or src_port in [20, 21, 22] or (proto_str == "TCP" and size >= 1400 and packet_rate > 15.0):
            return "File Transfer"
            
        # 3. Streaming indicators: high rate UDP packets
        if proto_str == "UDP" and (dst_port in [5004, 1935] or src_port in [5004, 1935] or (size > 1000 and packet_rate > 30.0)):
            return "Streaming"
            
        # 4. Default normal is Web Browsing (HTTP/HTTPS/DNS)
        return "Web Browsing"
