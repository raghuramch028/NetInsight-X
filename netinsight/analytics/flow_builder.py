import logging
import time

from netinsight.dashboard.models import Agent, PacketRecord

logger = logging.getLogger(__name__)

PROTOCOL_NAME_MAP = {
    "0": "MLD", "MLD": "MLD", "OTHER(0)": "MLD", "HOPOPT": "MLD",
    "1": "ICMP", "ICMP": "ICMP", "OTHER(1)": "ICMP",
    "2": "IGMP", "IGMP": "IGMP", "OTHER(2)": "IGMP",
    "6": "TCP", "TCP": "TCP", "OTHER(6)": "TCP",
    "17": "UDP", "UDP": "UDP", "OTHER(17)": "UDP",
    "41": "IPv6", "OTHER(41)": "IPv6",
    "47": "GRE", "OTHER(47)": "GRE",
    "50": "ESP", "OTHER(50)": "ESP",
    "51": "AH", "OTHER(51)": "AH",
    "58": "ICMPv6", "OTHER(58)": "ICMPv6",
    "88": "EIGRP", "OTHER(88)": "EIGRP",
    "89": "OSPF", "OTHER(89)": "OSPF",
    "112": "VRRP", "OTHER(112)": "VRRP",
}


def normalize_protocol_name(proto_str: str) -> str:
    """Normalizes raw protocol strings (e.g. 'OTHER(2)', '2', 'IGMP') to standard IANA protocol names."""
    if not proto_str:
        return "TCP"
    s = str(proto_str).strip().upper()
    if s in PROTOCOL_NAME_MAP:
        return PROTOCOL_NAME_MAP[s]
    import re
    m = re.search(r'\d+', s)
    if m:
        num_str = m.group(0)
        if num_str in PROTOCOL_NAME_MAP:
            return PROTOCOL_NAME_MAP[num_str]
    return s


def prepare_packet_record(agent: Agent, packet_dict: dict) -> PacketRecord:
    """Prepares an unsaved PacketRecord instance for batch insertion."""
    try:
        src_ip = packet_dict["src_ip"]
        dst_ip = packet_dict["dst_ip"]
        src_port = int(packet_dict.get("src_port", 0))
        dst_port = int(packet_dict.get("dst_port", 0))
        protocol = normalize_protocol_name(packet_dict["protocol"])
        size = int(packet_dict["size"])
        ttl = int(packet_dict.get("ttl", 64))
        pkt_ts = float(packet_dict.get("timestamp", time.time()))
        raw_tcp_seq = packet_dict.get("tcp_seq")
        tcp_seq = int(raw_tcp_seq) if raw_tcp_seq is not None else None

        return PacketRecord(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            size=size,
            timestamp=pkt_ts,
            ttl=ttl,
            tcp_seq=tcp_seq,
            agent=agent
        )
    except Exception as e:
        logger.error(f"Error preparing PacketRecord: {e}", exc_info=True)
        return None
