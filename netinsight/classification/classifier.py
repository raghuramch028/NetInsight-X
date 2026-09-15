import logging
import threading

from netinsight.classification.llm_classifier import LLMClassifier
from netinsight.config.labels import CLASS_LABELS

logger = logging.getLogger(__name__)

_KNOWN_LABELS = frozenset(CLASS_LABELS.values())


class TrafficClassifier:
    """Classifies network traffic into normal and threat categories using deterministic
    heuristic IDS rules with an NVIDIA cloud LLM fallback for traffic the rules can't label."""

    _DEFAULT_CONFIDENCE_THRESHOLD = 0.80

    def __init__(self, model_path: str | None = None, window_duration: float = 10.0):
        self.llm_classifier = LLMClassifier()
        self.last_engine_used = "NVIDIA DeepSeek AI"
        self.last_llm_latency_ms = 0.0
        self.last_llm_provider = "NVIDIA DeepSeek AI"
        self.last_llm_reasoning = ""
        self.last_llm_confidence: float | None = None

        self.ip_history = {}
        self.cache_lock = threading.Lock()
        self.window_duration = max(1.0, float(window_duration))

    def _get_confidence_threshold(self) -> float:
        """Reads SystemSettings.llm_confidence_threshold (admin-configurable via the Settings
        page). Local import avoids a module-level dependency from classification -> dashboard
        at import time; falls back to a fixed default if the settings row or DB isn't available
        (e.g. this classifier used outside a full Django request context)."""
        try:
            from netinsight.dashboard.models import SystemSettings
            settings_obj = SystemSettings.objects.first()
            if settings_obj is not None and settings_obj.llm_confidence_threshold is not None:
                return float(settings_obj.llm_confidence_threshold)
        except Exception as e:
            logger.debug(f"Could not read confidence threshold from SystemSettings: {e}")
        return self._DEFAULT_CONFIDENCE_THRESHOLD

    def update_ip_cache(
        self, src_ip: str, dst_ip: str, size: int, timestamp: float, dst_port: int = 0
    ) -> tuple[float, float, float, float]:
        """Updates cache and computes packet rate, unique destination IP frequency,
        unique destination port frequency, and average packet size.
        """
        with self.cache_lock:
            now = timestamp
            win_dur = max(1.0, float(self.window_duration))
            cutoff = now - win_dur

            if src_ip not in self.ip_history:
                self.ip_history[src_ip] = []

            # Store (timestamp, dst_ip, size, dst_port) tuple
            self.ip_history[src_ip].append((now, dst_ip, size, dst_port))

            # Prune old records
            self.ip_history[src_ip] = [item for item in self.ip_history[src_ip] if item[0] >= cutoff]

            if not self.ip_history[src_ip]:
                del self.ip_history[src_ip]
                return 0.0, 1.0, 1.0, float(size)

            history = self.ip_history[src_ip]
            packet_count = len(history)
            packet_rate = packet_count / win_dur

            unique_dests = len({item[1] for item in history})
            unique_ports = len({item[3] for item in history if item[3] > 0})
            total_bytes = sum(item[2] for item in history)
            avg_size = total_bytes / float(packet_count) if packet_count > 0 else float(size)

            MAX_IP_CACHE = 2000
            if len(self.ip_history) > MAX_IP_CACHE:
                stale_ips = [ip for ip, data in self.ip_history.items() if not data or (now - data[-1][0]) > win_dur]
                for ip in stale_ips:
                    del self.ip_history[ip]
                if len(self.ip_history) > MAX_IP_CACHE:
                    excess = len(self.ip_history) - (MAX_IP_CACHE - 500)
                    for ip in list(self.ip_history.keys())[:excess]:
                        del self.ip_history[ip]

            return float(packet_rate), float(unique_dests), float(unique_ports), float(avg_size)

    def _classify_rule_based(self, packet_dict: dict) -> str:
        """Executes enterprise-grade deterministic heuristic IDS rules based on real-world threat indicators."""
        src_ip = packet_dict.get("src_ip", "0.0.0.0")
        dst_ip = packet_dict.get("dst_ip", "0.0.0.0")
        size = int(packet_dict.get("size", 0))
        timestamp = float(packet_dict.get("timestamp", 0.0))
        proto_str = str(packet_dict.get("protocol", "TCP")).upper()
        dst_port = int(packet_dict.get("dst_port") or 0)
        src_port = int(packet_dict.get("src_port") or 0)

        packet_rate = packet_dict.get("packet_rate")
        conn_frequency = packet_dict.get("conn_frequency")
        unique_ports = packet_dict.get("unique_ports")
        avg_size = packet_dict.get("avg_size")

        if packet_rate is None or conn_frequency is None or unique_ports is None or avg_size is None:
            calc_rate, calc_freq, calc_ports, calc_avg_size = self.update_ip_cache(src_ip, dst_ip, size, timestamp, dst_port)
            if packet_rate is None:
                packet_rate = calc_rate
            if conn_frequency is None:
                conn_frequency = calc_freq
            if unique_ports is None:
                unique_ports = calc_ports
            if avg_size is None:
                avg_size = calc_avg_size

        # 1. Volumetric DDoS Attack Detection (Both Small Packet Floods AND Large Payload Amplification Saturation)
        throughput_bps = (packet_rate * avg_size * 8.0)
        is_small_pkt_flood = packet_rate > 800.0 and avg_size < 300
        is_amplification_flood = avg_size >= 1000 and throughput_bps >= 35_000_000.0  # 35 Mbps MTU saturation
        if is_small_pkt_flood or is_amplification_flood or packet_rate > 1000.0:
            return "DDoS"

        # 2. DoS Attack Detection (Single-target high-frequency packet floods)
        if packet_rate > 450.0:
            return "DoS"

        # 3. Mirai / IoT Botnet Detection (IoT Mgmt Ports 23/2323/7547/5555, UDP Amplification, or Layer 7 floods)
        iot_ports = {23, 2323, 7547, 5555}
        is_iot_scan = (dst_port in iot_ports or src_port in iot_ports) and packet_rate > 25.0
        is_udp_amplification = proto_str == "UDP" and packet_rate > 200.0 and conn_frequency > 15.0 and avg_size > 500
        is_l7_flood = (dst_port in {80, 443}) and packet_rate > 350.0 and avg_size > 400
        if is_iot_scan or is_udp_amplification or is_l7_flood:
            return "Mirai"

        # 4. Brute Force Authentication Attack Detection (Auth Login Ports 22 SSH, 23 Telnet, 3389 RDP, 445 SMB, 21 FTP)
        auth_ports = {22, 23, 3389, 445, 21, 110, 143}
        is_auth_target = (dst_port in auth_ports or src_port in auth_ports)
        # True brute force requires connection bursts with login attempt payloads, not raw volumetric floods
        if is_auth_target and (15.0 <= packet_rate <= 350.0) and (size < 1200):
            return "Brute Force"

        # 5. Reconnaissance / Port Scan Detection (True Port Scanning targets wide destination port sequences)
        # Legitimate heavy web browsing opens many IPs on standard HTTP/S ports (80/443), whereas real port scans probe many unique ports
        is_port_scan = unique_ports >= 20.0 or (conn_frequency > 35.0 and unique_ports >= 10.0)
        if is_port_scan:
            return "Reconnaissance"

        # 6. Other ICMP/Misc Attacks
        if proto_str == "ICMP" and packet_rate > 80.0:
            return "Other Attacks"

        return "Normal"

    def classify_packet(self, packet_dict: dict) -> str:
        """Performs hybrid LLM/heuristic inference on packet features."""
        rule_label = self._classify_rule_based(packet_dict)
        if rule_label != "Normal":
            self.last_engine_used = "Heuristics"
            self.last_llm_reasoning = f"Heuristic IDS Rule Triggered: Detected {rule_label} traffic pattern."
            return rule_label
        try:
            if hasattr(self.llm_classifier, 'classify_packet'):
                # classify_packet() returns a dict ({"label", "confidence", "reasoning"}) or None,
                # never a bare label string. The label must be extracted and validated here before
                # use — passing the raw dict through corrupts any CharField/threat_label consumer.
                llm_pred = self.llm_classifier.classify_packet(packet_dict)
                if isinstance(llm_pred, dict):
                    label = llm_pred.get("label")
                    confidence = llm_pred.get("confidence")
                    confidence = float(confidence) if isinstance(confidence, (int, float)) else None

                    if isinstance(label, str) and label in _KNOWN_LABELS:
                        # Suppress low-confidence non-Normal LLM threat reports rather than
                        # surfacing every borderline call as a security alert. svm_confidence_
                        # threshold (Settings page) previously had no effect on classification at
                        # all — this is what its own help text always claimed it did.
                        if label != "Normal" and confidence is not None:
                            threshold = self._get_confidence_threshold()
                            if confidence < threshold:
                                logger.info(
                                    f"LLM classified '{label}' with confidence {confidence:.2f}, below "
                                    f"the configured threshold {threshold:.2f}; suppressing to Normal."
                                )
                                label = "Normal"

                        self.last_engine_used = "NVIDIA DeepSeek AI"
                        self.last_llm_latency_ms = getattr(self.llm_classifier, 'last_llm_latency_ms', 0.0)
                        self.last_llm_provider = "NVIDIA DeepSeek AI"
                        self.last_llm_reasoning = getattr(self.llm_classifier, 'last_llm_reasoning', "")
                        self.last_llm_confidence = confidence
                        return label
                    logger.warning(f"LLM returned an unrecognized label {label!r}; falling back to Normal.")
        except Exception as e:
            logger.error(f"LLM Classification error: {e}")

        return "Normal"

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
