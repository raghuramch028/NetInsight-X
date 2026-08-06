import logging
import threading

from netinsight.classification.llm_classifier import LLMClassifier

logger = logging.getLogger(__name__)


class TrafficClassifier:
    """Classifies network traffic into normal and threat categories using a trained SVM."""

    def __init__(self, model_path: str | None = None, window_duration: float = 10.0):
        self.llm_classifier = LLMClassifier()
        self.last_engine_used = "NVIDIA DeepSeek AI"
        self.last_llm_latency_ms = 0.0
        self.last_llm_provider = "NVIDIA DeepSeek AI"
        self.last_llm_reasoning = ""

        self.ip_history = {}
        self.cache_lock = threading.Lock()
        self.window_duration = max(1.0, float(window_duration))

    def update_ip_cache(self, src_ip: str, dst_ip: str, size: int, timestamp: float) -> tuple[float, float]:
        """Updates cache and computes packet rate and unique connection frequency."""
        with self.cache_lock:
            now = timestamp
            win_dur = max(1.0, float(self.window_duration))
            cutoff = now - win_dur

            if src_ip not in self.ip_history:
                self.ip_history[src_ip] = []

            # Add current record
            self.ip_history[src_ip].append((now, dst_ip, size))

            # Prune old records
            self.ip_history[src_ip] = [item for item in self.ip_history[src_ip] if item[0] >= cutoff]

            # Prune empty IP entries to prevent unbounded memory growth
            if not self.ip_history[src_ip]:
                del self.ip_history[src_ip]
                return 0.0, 1.0

            history = self.ip_history[src_ip]
            packet_count = len(history)
            packet_rate = packet_count / win_dur

            unique_dests = len({item[1] for item in history})

            MAX_IP_CACHE = 2000
            if len(self.ip_history) > MAX_IP_CACHE:
                # Evict oldest 500 IP entries to prevent unbounded memory growth
                stale_ips = [ip for ip, data in self.ip_history.items() if not data or (now - data[-1][0]) > win_dur]
                for ip in stale_ips:
                    del self.ip_history[ip]
                if len(self.ip_history) > MAX_IP_CACHE:
                    # Force prune oldest keys if still exceeding cap
                    excess = len(self.ip_history) - (MAX_IP_CACHE - 500)
                    for ip in list(self.ip_history.keys())[:excess]:
                        del self.ip_history[ip]

            return float(packet_rate), float(unique_dests)

    def _classify_rule_based(self, packet_dict: dict) -> str:
        """Executes fast, deterministic heuristic IDS rules on packet dictionary."""
        src_ip = packet_dict.get("src_ip", "0.0.0.0")
        dst_ip = packet_dict.get("dst_ip", "0.0.0.0")
        size = int(packet_dict.get("size", 0))
        timestamp = float(packet_dict.get("timestamp", 0.0))
        proto_str = str(packet_dict.get("protocol", "TCP")).upper()
        dst_port = int(packet_dict.get("dst_port") or 0)
        src_port = int(packet_dict.get("src_port") or 0)

        packet_rate = packet_dict.get("packet_rate")
        conn_frequency = packet_dict.get("conn_frequency")

        if packet_rate is None or conn_frequency is None:
            packet_rate, _ = self.update_ip_cache(src_ip, dst_ip, size, timestamp)
            conn_frequency = 2.0

        if packet_rate > 1000.0 and size < 200:
            return "DDoS"
        if packet_rate > 500.0:
            return "DoS"
        if proto_str == "UDP" and packet_rate > 300.0 and conn_frequency > 30.0:
            return "Mirai"
        if (dst_port in [22, 23, 3389, 445] or src_port in [22, 23, 3389, 445]) and packet_rate > 50.0:
            return "Brute Force"
        if conn_frequency > 50.0 or (packet_rate > 30.0 and conn_frequency > 25.0):
            return "Reconnaissance"
        if proto_str == "ICMP" and packet_rate > 100.0:
            return "Other Attacks"
        return "Normal"

    def classify_packet(self, packet_dict: dict) -> str:
        """Performs hybrid LLM/heuristic inference on packet features."""
        rule_label = self._classify_rule_based(packet_dict)
        if rule_label != "Normal":
            self.last_engine_used = "Heuristics"
            return rule_label
        try:
            if hasattr(self.llm_classifier, 'classify_packet'):
                llm_pred = self.llm_classifier.classify_packet(packet_dict)
                if llm_pred is not None:
                    self.last_engine_used = "NVIDIA DeepSeek AI"
                    self.last_llm_latency_ms = getattr(self.llm_classifier, 'last_llm_latency_ms', 0.0)
                    self.last_llm_provider = "NVIDIA DeepSeek AI"
                    self.last_llm_reasoning = getattr(self.llm_classifier, 'last_llm_reasoning', "")
                    return llm_pred
        except Exception as e:
            logger.error(f"LLM Classification error: {e}")

        return "Normal"

    def classify_batch(self, features_df):
        """Classifies a batch of features via LLM or fallback XGBoost."""
        predictions = None
        try:
            if hasattr(self.llm_classifier, 'classify_batch'):
                predictions = self.llm_classifier.classify_batch(features_df)
        except Exception as e:
            logger.error(f"LLM Batch Classification error: {e}")

        if predictions is not None:
            self.last_engine_used = "NVIDIA DeepSeek AI"
            self.last_llm_latency_ms = getattr(self.llm_classifier, 'last_llm_latency_ms', 0.0)
            self.last_llm_provider = "NVIDIA DeepSeek AI"
            self.last_llm_reasoning = getattr(self.llm_classifier, 'last_llm_reasoning', "")
            return predictions

        return ["Normal"] * len(features_df)

# Shared module singleton instance to ensure IP history cache is shared across threads/views
_shared_classifier = None
_shared_classifier_lock = threading.Lock()

def get_shared_classifier() -> TrafficClassifier:
    """Returns the process-wide shared TrafficClassifier singleton instance."""
    global _shared_classifier
    if _shared_classifier is None:
        with _shared_classifier_lock:
            if _shared_classifier is None:
                _shared_classifier = TrafficClassifier()
    return _shared_classifier
