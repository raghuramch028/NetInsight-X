import time
import queue
import random
import threading
import logging
from scapy.all import sniff
from netinsight.config import settings
from netinsight.capture.parser import PacketParser
from netinsight.database import db_manager

logger = logging.getLogger(__name__)

class LiveMonitor:
    """Manages packet capture threads, queues, database storage, and metric calculations."""
    
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=10000)
        self.parser = PacketParser()
        self.is_running = False
        self.sniffer_thread = None
        self.writer_thread = None
        
        # Performance tracking metrics inside the monitoring window
        self.bytes_in_window = 0
        self.packets_in_window = 0
        self.latencies_in_window = []
        self.window_lock = threading.Lock()
        
        # Running capture performance metrics (for evaluation methodology)
        self.total_captured_packets = 0
        self.total_dropped_packets = 0

    def packet_callback(self, packet) -> None:
        """Callback from Scapy sniffer. Parses and queues the packet.
        
        This callback must execute quickly to avoid dropping packets.
        """
        self.total_captured_packets += 1
        try:
            parsed = self.parser.parse(packet)
            if parsed:
                try:
                    self.packet_queue.put_nowait(parsed)
                except queue.Full:
                    self.total_dropped_packets += 1
                    logger.warning("Packet queue full. Dropped a packet.")
        except Exception as e:
            logger.error(f"Error parsing packet in callback: {e}", exc_info=True)

    def run_live_sniffer(self) -> None:
        """Sniffs packets from the selected network interface using Scapy."""
        logger.info(f"Starting live Scapy sniffer on interface: {settings.CAPTURE_INTERFACE or 'Default'}")
        try:
            sniff(
                iface=settings.CAPTURE_INTERFACE,
                prn=self.packet_callback,
                store=0,
                stop_filter=lambda p: not self.is_running
            )
        except Exception as e:
            logger.error(f"Error in Scapy live sniffer: {e}", exc_info=True)
            self.is_running = False

    def run_demo_replay(self) -> None:
        """Simulates live packet arrivals for testing and project presentations (Demonstration Mode)."""
        logger.info("Starting NetInsight-X Demonstration Replay Mode...")
        
        ips = [
            "192.168.1.1", "192.168.1.15", "192.168.1.22", "192.168.1.33",
            "10.0.0.4", "10.0.0.8", "8.8.8.8", "1.1.1.1", "142.250.190.46"
        ]
        
        protocols = ["TCP", "UDP", "ICMP"]
        
        # Simulate active state cycles (Normal, Busy, Congested, Failure)
        # to generate realistic data patterns for Markov/MDP validation
        state_cycle = ["NORMAL", "NORMAL", "BUSY", "CONGESTED", "FAILURE", "CONGESTED", "BUSY"]
        cycle_idx = 0
        cycle_duration = 30  # Change state pattern every 30 seconds
        last_cycle_change = time.time()
        
        while self.is_running:
            now = time.time()
            if now - last_cycle_change > cycle_duration:
                cycle_idx = (cycle_idx + 1) % len(state_cycle)
                last_cycle_change = now
                logger.info(f"Replay mode state pattern changed to: {state_cycle[cycle_idx]}")
                
            current_pattern = state_cycle[cycle_idx]
            
            # Determine packet generation rate based on simulated network state
            if current_pattern == "NORMAL":
                pkt_count = random.randint(5, 15)
                delay = 0.1
            elif current_pattern == "BUSY":
                pkt_count = random.randint(30, 80)
                delay = 0.05
            elif current_pattern == "CONGESTED":
                pkt_count = random.randint(150, 250)
                delay = 0.02
            else:  # FAILURE (either high loss or saturated)
                pkt_count = random.randint(200, 300)
                delay = 0.01
                
            for _ in range(pkt_count):
                src = random.choice(ips[:4])  # LAN src IPs
                dst = random.choice(ips[4:])  # WAN dst IPs
                proto = random.choice(protocols)
                size = random.randint(64, 1500)
                
                # Assign ports
                src_port = random.randint(1024, 65535)
                if proto == "TCP":
                    dst_port = random.choice([80, 443, 21, 22, 445])
                elif proto == "UDP":
                    dst_port = random.choice([53, 5004, 123])
                else:
                    dst_port = 0
                    
                # Introduce packet loss (retransmissions) or latency spikes based on state
                latency_est = None
                is_retransmission = False
                
                if current_pattern == "NORMAL":
                    latency_est = random.uniform(0.005, 0.020) # 5-20ms
                    is_retransmission = (random.random() < 0.01)
                elif current_pattern == "BUSY":
                    latency_est = random.uniform(0.020, 0.050) # 20-50ms
                    is_retransmission = (random.random() < 0.03)
                elif current_pattern == "CONGESTED":
                    latency_est = random.uniform(0.080, 0.180) # 80-180ms
                    is_retransmission = (random.random() < 0.08)
                else:  # FAILURE
                    latency_est = random.uniform(0.200, 0.500) # 200-500ms
                    is_retransmission = (random.random() < 0.15) # 15% retransmissions
                    
                # Queue the mock packet
                mock_pkt = {
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "size": size,
                    "timestamp": now,
                    "ttl": random.choice([64, 128]),
                    "latency_est": latency_est if random.random() < 0.3 else None,
                    "is_retransmission": is_retransmission
                }
                
                try:
                    self.packet_queue.put_nowait(mock_pkt)
                    self.total_captured_packets += 1
                except queue.Full:
                    self.total_dropped_packets += 1
                    
            time.sleep(delay)

    def classify_state_by_metrics(self, util: float, loss: float) -> str:
        """Classifies network state using configurable thresholds from settings.py."""
        thresholds = settings.STATE_THRESHOLDS
        
        # Check Failure conditions
        if util >= thresholds["FAILURE"]["util_min"] or loss >= thresholds["FAILURE"]["loss_min"]:
            return "FAILURE"
            
        # Check Congested conditions
        if (thresholds["CONGESTED"]["util_min"] <= util < thresholds["CONGESTED"]["util_max"] 
                and loss < thresholds["CONGESTED"]["loss_max"]):
            return "CONGESTED"
            
        # Check Busy conditions
        if (thresholds["BUSY"]["util_min"] <= util < thresholds["BUSY"]["util_max"] 
                and loss < thresholds["BUSY"]["loss_max"]):
            return "BUSY"
            
        # Default to NORMAL
        return "NORMAL"

    def run_writer_worker(self) -> None:
        """Consumes pre-parsed packets from the queue, batch-writes them, and updates metrics."""
        logger.info("Starting database writer and statistics collector worker...")
        
        batch_size = 100
        packet_batch = []
        
        last_metrics_calc = time.time()
        metrics_window_seconds = 2.0
        
        while self.is_running or not self.packet_queue.empty():
            try:
                # Retrieve packet from queue with a short timeout to prevent blocking
                parsed_packet = self.packet_queue.get(timeout=0.1)
                packet_batch.append(parsed_packet)
                
                # Accumulate window statistics under lock
                with self.window_lock:
                    self.bytes_in_window += parsed_packet["size"]
                    self.packets_in_window += 1
                    if parsed_packet["latency_est"] is not None:
                        self.latencies_in_window.append(parsed_packet["latency_est"])
                
                self.packet_queue.task_done()
            except queue.Empty:
                pass
            
            # Flush batch to SQL
            if len(packet_batch) >= batch_size or (not self.is_running and packet_batch):
                db_manager.save_packets_bulk(packet_batch)
                
                # Update active device statistics for each packet in the batch
                for pkt in packet_batch:
                    db_manager.update_active_device(pkt["src_ip"], pkt["timestamp"], pkt["size"])
                
                packet_batch.clear()
            
            # Calculate and save metrics periodically
            now = time.time()
            delta_t = now - last_metrics_calc
            if delta_t >= metrics_window_seconds:
                with self.window_lock:
                    bytes_captured = self.bytes_in_window
                    packets_captured = self.packets_in_window
                    latencies = list(self.latencies_in_window)
                    
                    # Reset window variables
                    self.bytes_in_window = 0
                    self.packets_in_window = 0
                    self.latencies_in_window.clear()
                    
                last_metrics_calc = now
                
                # --- Calculations ---
                # Throughput in bits per second (bps)
                throughput = (bytes_captured * 8.0) / delta_t
                # Packet rate in packets per second (pps)
                packet_rate = packets_captured / delta_t
                # Utilization relative to configurable link capacity
                bandwidth_util = (throughput / settings.LINK_CAPACITY) * 100.0
                
                # Latency approximation: average of handshake RTTs, fallback to inter-packet delays
                if latencies:
                    avg_latency = sum(latencies) / len(latencies)
                else:
                    avg_latency = self.parser.get_average_inter_packet_delay()
                    
                # Packet loss approximation: TCP retransmission rate
                estimated_loss = self.parser.get_estimated_loss_rate()
                
                # Log metrics into database
                db_manager.save_metric(now, throughput, packet_rate, bandwidth_util, avg_latency, estimated_loss)
                
                # Classify and log network state to state_history
                net_state = self.classify_state_by_metrics(bandwidth_util / 100.0, estimated_loss / 100.0)
                db_manager.save_state_history(now, net_state, bandwidth_util / 100.0, estimated_loss / 100.0, avg_latency)
                
                logger.debug(
                    f"Metrics: Util={bandwidth_util:.2f}%, "
                    f"Throughput={throughput/1e6:.2f}Mbps, "
                    f"Rate={packet_rate:.1f}pps, "
                    f"State={net_state}, "
                    f"Loss={estimated_loss:.2f}%"
                )
                
        # Flush any remaining items in the queue/batch
        if packet_batch:
            db_manager.save_packets_bulk(packet_batch)
            for pkt in packet_batch:
                db_manager.update_active_device(pkt["src_ip"], pkt["timestamp"], pkt["size"])
            packet_batch.clear()

    def start(self) -> None:
        """Starts the capture and consumer threads."""
        if self.is_running:
            return
            
        logger.info("Initializing monitoring system...")
        db_manager.init_db()
        self.is_running = True
        
        # Start DB consumer writer
        self.writer_thread = threading.Thread(target=self.run_writer_worker, name="WriterWorker")
        self.writer_thread.daemon = True
        self.writer_thread.start()
        
        # Start packet sniffer/replay producer
        if settings.DEMO_MODE:
            self.sniffer_thread = threading.Thread(target=self.run_demo_replay, name="DemoReplay")
        else:
            self.sniffer_thread = threading.Thread(target=self.run_live_sniffer, name="LiveSniffer")
            
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        logger.info("Monitoring system started successfully.")

    def stop(self) -> None:
        """Stops the capture and consumer threads."""
        if not self.is_running:
            return
            
        logger.info("Stopping monitoring system...")
        self.is_running = False
        
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            self.sniffer_thread.join(timeout=3.0)
            
        if self.writer_thread and self.writer_thread.is_alive():
            self.writer_thread.join(timeout=3.0)
            
        logger.info("Monitoring system stopped.")
        
    def get_capture_rate(self) -> float:
        """Returns the capture success rate (captured vs total processed)."""
        processed = self.total_captured_packets + self.total_dropped_packets
        if processed == 0:
            return 100.0
        return (self.total_captured_packets / processed) * 100.0
