import logging
import time
from datetime import timedelta
from django.utils import timezone
from netinsight.dashboard.models import PacketRecord, FlowRecord, ThreatHistory
from netinsight.classification.classifier import TrafficClassifier

logger = logging.getLogger(__name__)
classifier = TrafficClassifier()

def process_incoming_packet(agent, pkt_data: dict) -> None:
    """Saves raw packet, builds bi-directional flows, and performs SVM classification."""
    try:
        src_ip = pkt_data["src_ip"]
        dst_ip = pkt_data["dst_ip"]
        src_port = int(pkt_data.get("src_port", 0))
        dst_port = int(pkt_data.get("dst_port", 0))
        protocol = pkt_data["protocol"]
        size = int(pkt_data["size"])
        ttl = int(pkt_data.get("ttl", 64))
        timestamp = float(pkt_data.get("timestamp", time.time()))

        # 1. Save PacketRecord
        PacketRecord.objects.create(
            agent=agent,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=size,
            ttl=ttl,
            timestamp=timestamp
        )

        # 2. Build normalized bi-directional flow key
        flow_key = f"{min(src_ip, dst_ip)}_{max(src_ip, dst_ip)}_{min(src_port, dst_port)}_{max(src_port, dst_port)}_{protocol}"

        # 3. Retrieve or create FlowRecord active within a 30s window
        cutoff_time = timestamp - 30.0
        flow = FlowRecord.objects.filter(
            agent=agent,
            flow_key=flow_key,
            end_time__gte=cutoff_time
        ).order_by("-end_time").first()

        if flow:
            flow.packet_count += 1
            flow.byte_count += size
            flow.end_time = timestamp
            flow.duration = flow.end_time - flow.start_time
            flow.avg_packet_size = float(flow.byte_count) / flow.packet_count
        else:
            flow = FlowRecord(
                agent=agent,
                flow_key=flow_key,
                start_time=timestamp,
                end_time=timestamp,
                duration=0.0,
                packet_count=1,
                byte_count=size,
                avg_packet_size=float(size),
                protocol=protocol
            )

        # 4. Feature Extraction & SVM Threat Classification
        # Protocol mapping
        proto_map = {"TCP": 6.0, "UDP": 17.0, "ICMP": 1.0}
        protocol_val = proto_map.get(protocol.upper(), 0.0)

        # Estimate connection frequency (unique destinations visited by the agent in last 10m)
        window_start = timestamp - 600.0
        unique_dests = PacketRecord.objects.filter(
            agent=agent,
            src_ip=src_ip,
            timestamp__gte=window_start
        ).values("dst_ip").distinct().count()

        # Calculate packet rate
        packet_rate = float(flow.packet_count) / max(0.001, flow.duration)

        # Construct packet payload dictionary for classification compatibility
        classify_payload = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "size": int(flow.avg_packet_size),
            "timestamp": timestamp,
            "protocol": protocol,
            "latency_est": 0.015,  # Heuristic fallback on server
            "packet_rate": packet_rate,
            "conn_frequency": float(unique_dests)
        }

        # Classify threat label using trained model
        threat_label = classifier.classify_packet(classify_payload)
        flow.threat_label = threat_label
        flow.save()

        # 5. Log Security Alerts in ThreatHistory if threat is not Normal
        if threat_label != "Normal":
            # Map labels to severity levels
            severity = "Warning"
            if threat_label in ["DoS", "DDoS", "Mirai"]:
                severity = "Critical"
            elif threat_label == "Normal":
                severity = "Information"

            # Check if this alert was already logged recently to avoid spamming the logs
            recent_alert = ThreatHistory.objects.filter(
                agent=agent,
                threat_type=threat_label,
                timestamp__gte=timezone.now() - timedelta(seconds=10)
            ).exists()

            if not recent_alert:
                ThreatHistory.objects.create(
                    agent=agent,
                    threat_type=threat_label,
                    severity=severity
                )

    except Exception as e:
        logger.error(f"Error in Flow Builder for packet: {e}", exc_info=True)
