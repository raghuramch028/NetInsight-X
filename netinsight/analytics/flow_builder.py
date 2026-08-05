import logging
import time
from datetime import timedelta

from django.utils import timezone

from netinsight.classification.classifier import get_shared_classifier
from netinsight.dashboard.models import Agent, FlowRecord, PacketRecord, ThreatHistory

logger = logging.getLogger(__name__)
classifier = get_shared_classifier()

def prepare_packet_record(agent: Agent, packet_dict: dict) -> PacketRecord:
    """Prepares an unsaved PacketRecord instance for batch insertion, after updating flow aggregations."""
    try:
        src_ip = packet_dict["src_ip"]
        dst_ip = packet_dict["dst_ip"]
        src_port = int(packet_dict.get("src_port", 0))
        dst_port = int(packet_dict.get("dst_port", 0))
        protocol = packet_dict["protocol"]
        size = int(packet_dict["size"])
        ttl = int(packet_dict.get("ttl", 64))
        pkt_ts = float(packet_dict.get("timestamp", time.time()))

        # 2. Build normalized bi-directional flow key
        flow_key = f"{min(src_ip, dst_ip)}_{max(src_ip, dst_ip)}_{min(src_port, dst_port)}_{max(src_port, dst_port)}_{protocol}"

        # 3. Retrieve or create FlowRecord active within a 30s window
        cutoff_time = pkt_ts - 30.0
        flow = FlowRecord.objects.filter(
            agent=agent,
            flow_key=flow_key,
            end_time__gte=cutoff_time
        ).order_by("-end_time").first()

        if flow:
            flow.packet_count += 1
            flow.byte_count += size
            flow.end_time = pkt_ts
            flow.duration = flow.end_time - flow.start_time
            flow.avg_packet_size = float(flow.byte_count) / flow.packet_count
        else:
            flow = FlowRecord(
                agent=agent,
                flow_key=flow_key,
                start_time=pkt_ts,
                end_time=pkt_ts,
                duration=0.0,
                packet_count=1,
                byte_count=size,
                avg_packet_size=float(size),
                protocol=protocol
            )

        # 4. Feature Extraction & SVM Threat Classification

        # Estimate connection frequency (unique destinations visited by the agent in last 10m)
        window_start = pkt_ts - 600.0
        unique_dests = PacketRecord.objects.filter(
            agent=agent,
            src_ip=src_ip,
            timestamp__gte=window_start
        ).values("dst_ip").distinct().count()

        # Calculate packet rate normalized to time (packets per second)
        # Clamp minimum effective duration to 0.5s to avoid rate inflation on instant single packets
        effective_duration = max(flow.duration, 0.5)
        packet_rate = float(flow.packet_count) / effective_duration

        # Construct packet payload dictionary for classification compatibility
        classify_payload = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "size": int(flow.avg_packet_size),
            "timestamp": pkt_ts,
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
            severity = "Critical" if threat_label in ["DoS", "DDoS", "Mirai"] else "Warning"

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

        return PacketRecord(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=size,
            timestamp=pkt_ts,
            ttl=ttl,
            agent=agent
        )

    except Exception as e:
        logger.error(f"Error in Flow Builder for packet: {e}", exc_info=True)
