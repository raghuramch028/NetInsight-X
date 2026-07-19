import time
import sys
import signal
from agent.logger import logger
from agent.collector import TelemetryCollector
from agent.sniffer import PacketSniffer
from agent.sender import TelemetrySender
from agent.utils import get_mac_address
from agent import config

class NetInsightAgent:
    """Coordinates startup registration, telemetry gathering, and asynchronous sniffing."""

    def __init__(self):
        self.collector = TelemetryCollector()
        self.sniffer = PacketSniffer()
        self.sender = TelemetrySender()
        self.failed_packets_queue = []
        self.max_failed_packets = 10000
        self.is_running = False

    def handle_shutdown(self, signum, frame):
        """Callback to handle terminations gracefully."""
        logger.info("Shutdown signal received. Tearing down...")
        self.stop()
        sys.exit(0)

    def stop(self):
        """Stops background threads and capture sessions."""
        self.is_running = False
        self.sniffer.stop()
        logger.info("Agent stopped.")

    def run(self):
        """Executes the registration sequence and starts telemetry loops."""
        # Bind shutdown handlers
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

        logger.info("Starting NetInsight-X Telemetry Agent...")

        # 1. Device Registration Sequence
        mac_addr = get_mac_address()
        hostname = self.collector.hostname
        device_type = self.collector.os_type
        vendor = self.collector.vendor

        logger.info(f"Local Host Details: MAC={mac_addr}, Hostname={hostname}, OS={device_type}")
        
        # Blocks until registered
        self.sender.register(mac_addr, hostname, device_type, vendor)

        # 2. Start Packet Capture Session
        self.sniffer.start()

        # 3. Main Telemetry Upload Loop
        self.is_running = True
        logger.info(f"Starting telemetry loop (Interval: {config.TELEMETRY_INTERVAL}s)...")

        backoff = config.TELEMETRY_INTERVAL
        max_backoff = 60.0

        while self.is_running:
            start_time = time.time()

            # Gather host stats
            stats = self.collector.collect()

            # Get new packets and combine with previously failed packets
            new_packets = self.sniffer.get_and_clear_packets()
            packets_to_send = self.failed_packets_queue + new_packets

            # Bounded limit for transmission safety
            if len(packets_to_send) > self.max_failed_packets:
                logger.warning(f"Failed packet queue exceeded maximum limit ({self.max_failed_packets}). Dropping oldest packets.")
                packets_to_send = packets_to_send[-self.max_failed_packets:]

            # Try uploading
            success = self.sender.send_telemetry(stats, packets_to_send)

            if success:
                # Clear queue on success
                self.failed_packets_queue.clear()
                backoff = config.TELEMETRY_INTERVAL  # Reset backoff on success
            else:
                # Save queue on failure
                self.failed_packets_queue = packets_to_send
                logger.warning(f"Telemetry upload failed. Queued {len(self.failed_packets_queue)} packets for next attempt.")
                
                # Apply exponential backoff delay for the next loop run
                backoff = min(backoff * 1.5, max_backoff)

            # Rest of the loop interval calculation
            elapsed = time.time() - start_time
            sleep_time = max(0.1, backoff - elapsed)
            time.sleep(sleep_time)

if __name__ == "__main__":
    agent = NetInsightAgent()
    try:
        agent.run()
    except Exception as e:
        logger.critical(f"Unhandled exception in agent main: {e}", exc_info=True)
        agent.stop()
        sys.exit(1)
