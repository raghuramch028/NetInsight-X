import logging
import time

from scapy.all import IP, TCP, UDP, Packet

logger = logging.getLogger(__name__)

class PacketParser:
    """Parses raw Scapy packets and estimates network metrics like latency and packet loss.

    This class utilizes passive heuristics suitable for a live monitor.
    """

    def __init__(self):
        # Maps TCP flow keys to handshake timestamps
        # flow_key: (src_ip, src_port, dst_ip, dst_port)
        self.syn_tracker = {}       # flow_key -> timestamp of SYN
        self.syn_ack_tracker = {}   # reverse_flow_key -> timestamp of SYN-ACK

        # Maps flow keys to their last packet arrival timestamp (for inter-packet delay estimation)
        self.last_packet_time = {}  # flow_key -> timestamp
        self.rolling_inter_packet_delays = []
        self.max_delay_history = 1000

        # Maps TCP flow keys to a set of observed sequence numbers to detect duplicate sequence retransmissions
        self.flow_seq_numbers = {}  # flow_key -> set of sequence numbers
        self.total_packets_per_flow = {} # flow_key -> count
        self.retransmitted_packets_per_flow = {} # flow_key -> count

        # Protocols mapping
        self.proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple:
        """Returns a unique flow key tuple."""
        return (src_ip, src_port, dst_ip, dst_port)

    def parse(self, packet: Packet) -> dict | None:
        """Decodes a Scapy packet and extracts network features.

        Also calculates passive estimations of latency and packet loss.
        """
        if not packet.haslayer(IP):
            return None

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        protocol = self.proto_map.get(proto_num, f"OTHER({proto_num})")
        size = len(packet)
        timestamp = float(packet.time) if packet.time else time.time()
        ttl = ip_layer.ttl

        src_port = 0
        dst_port = 0
        latency_est = None
        is_retransmission = False

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = int(tcp_layer.sport)
            dst_port = int(tcp_layer.dport)

            flow_key = self.get_flow_key(src_ip, src_port, dst_ip, dst_port)
            rev_flow_key = self.get_flow_key(dst_ip, dst_port, src_ip, src_port)

            # --- Latency Estimation (TCP Handshake RTT Heuristic) ---
            flags = tcp_layer.flags
            if flags & 0x02:  # SYN flag is set
                if not (flags & 0x10):  # SYN only (not SYN-ACK)
                    self.syn_tracker[flow_key] = timestamp
                else:  # SYN-ACK
                    self.syn_ack_tracker[rev_flow_key] = timestamp
                    # If we tracked the original SYN, we can estimate RTT
                    if rev_flow_key in self.syn_tracker:
                        latency_est = timestamp - self.syn_tracker[rev_flow_key]
                        del self.syn_tracker[rev_flow_key]
            elif flags & 0x10 and flow_key in self.syn_ack_tracker:  # ACK flag is set
                # If we tracked a SYN-ACK, compute RTT on first ACK
                latency_est = timestamp - self.syn_ack_tracker[flow_key]
                del self.syn_ack_tracker[flow_key]

            # --- Packet Loss Estimation (TCP Retransmission Heuristic) ---
            seq_num = tcp_layer.seq
            self.total_packets_per_flow[flow_key] = self.total_packets_per_flow.get(flow_key, 0) + 1

            if flow_key not in self.flow_seq_numbers:
                self.flow_seq_numbers[flow_key] = set()

            # If sequence number was already seen, classify as retransmission (potential packet loss marker)
            # Avoid counting empty ACKs as duplicate seqs by checking if payload size > 0
            payload_len = len(tcp_layer.payload)
            if payload_len > 0:
                if seq_num in self.flow_seq_numbers[flow_key]:
                    is_retransmission = True
                    self.retransmitted_packets_per_flow[flow_key] = self.retransmitted_packets_per_flow.get(flow_key, 0) + 1
                else:
                    self.flow_seq_numbers[flow_key].add(seq_num)
                    # Limit memory footprint
                    if len(self.flow_seq_numbers[flow_key]) > 200:
                        self.flow_seq_numbers[flow_key].pop()

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = int(udp_layer.sport)
            dst_port = int(udp_layer.dport)

        # --- Latency Estimation Fallback (Inter-packet gap) ---
        # If latency wasn't estimated via TCP handshake, check inter-packet arrival gaps
        flow_key = self.get_flow_key(src_ip, src_port, dst_ip, dst_port)
        if latency_est is None:
            if flow_key in self.last_packet_time:
                gap = timestamp - self.last_packet_time[flow_key]
                if 0.0001 < gap < 5.0:  # Sensible range for live traffic gaps
                    self.rolling_inter_packet_delays.append(gap)
                    if len(self.rolling_inter_packet_delays) > self.max_delay_history:
                        self.rolling_inter_packet_delays.pop(0)
            self.last_packet_time[flow_key] = timestamp

        # Return pre-parsed dictionary
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "timestamp": timestamp,
            "ttl": ttl,
            "latency_est": latency_est,
            "is_retransmission": is_retransmission
        }

    def get_average_inter_packet_delay(self) -> float:
        """Returns the average inter-packet arrival delay (fallback latency approximation)."""
        if not self.rolling_inter_packet_delays:
            return 0.015  # Default base approximation (15ms)
        return sum(self.rolling_inter_packet_delays) / len(self.rolling_inter_packet_delays)

    def get_estimated_loss_rate(self) -> float:
        """Calculates estimated packet loss based on TCP retransmissions."""
        total = sum(self.total_packets_per_flow.values())
        retrans = sum(self.retransmitted_packets_per_flow.values())
        if total == 0:
            return 0.0
        return (retrans / total) * 100.0
