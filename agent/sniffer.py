import threading
import time
from scapy.all import IP, TCP, UDP, AsyncSniffer
from agent.logger import logger
from agent import config

class PacketSniffer:
    """Uses Scapy to perform local packet capture and extract metadata from packet headers."""

    def __init__(self):
        self.packet_buffer = []
        self.buffer_lock = threading.Lock()
        self.sniffer = None
        self.is_running = False
        self.proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

    def packet_callback(self, packet) -> None:
        """Processes a single sniffed packet, extracts headers, and stores in buffer."""
        if not packet.haslayer(IP):
            return

        try:
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

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)

            pkt_dict = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "size": size,
                "ttl": ttl,
                "timestamp": timestamp
            }

            with self.buffer_lock:
                self.packet_buffer.append(pkt_dict)
                # Keep packet buffer bounded in case server uploads fail repeatedly
                if len(self.packet_buffer) > 10000:
                    self.packet_buffer.pop(0)

        except Exception as e:
            logger.error(f"Error parsing packet in callback: {e}")

    def start(self) -> None:
        """Starts Scapy AsyncSniffer in a background thread."""
        if self.is_running:
            return

        logger.info("Initializing packet capture thread...")
        self.is_running = True
        try:
            self.sniffer = AsyncSniffer(
                iface=config.CAPTURE_INTERFACE,
                prn=self.packet_callback,
                store=0
            )
            self.sniffer.start()
            logger.info("Packet capture thread started successfully.")
        except Exception as e:
            logger.error(f"Failed to start Scapy AsyncSniffer: {e}", exc_info=True)
            self.is_running = False

    def stop(self) -> None:
        """Stops the Scapy AsyncSniffer."""
        if not self.is_running:
            return

        logger.info("Stopping packet capture thread...")
        self.is_running = False
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception as e:
                logger.error(f"Error stopping Scapy AsyncSniffer: {e}")
        logger.info("Packet capture thread stopped.")

    def get_and_clear_packets(self) -> list[dict]:
        """Retrieves all buffered packet records and empties the list thread-safely."""
        with self.buffer_lock:
            packets = list(self.packet_buffer)
            self.packet_buffer.clear()
            return packets
