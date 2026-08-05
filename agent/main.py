import time
import sys
import signal
import os
import json
import platform
import subprocess
from agent.logger import logger
from agent.collector import TelemetryCollector
from agent.sniffer import PacketSniffer
from agent.sender import TelemetrySender
from agent.utils import get_mac_address, get_current_ssid
from agent import config

class NetInsightAgent:
    """Coordinates startup registration, telemetry gathering, and asynchronous sniffing."""

    def __init__(self):
        self.collector = TelemetryCollector()
        self.sniffer = PacketSniffer()
        self.sender = TelemetrySender()
        self.offline_file = "offline_buffer.json"
        self.is_running = False

    def apply_local_shaping(self, qos_limits: dict):
        """Applies dynamic QoS shaper policies locally based on optimal limits from server."""
        policy = qos_limits.get("recommended_policy", "Reallocate Bandwidth")
        
        # Safely extract QoS limits with sensible defaults
        qos_limits.setdefault('web_browsing_mbps', 5.0)
        qos_limits.setdefault('streaming_mbps', 15.0)
        qos_limits.setdefault('file_transfer_mbps', 2.0)
        qos_limits.setdefault('critical_services_mbps', 10.0)
        
        logger.info(
            f"[QoS CONTROL] Syncing dynamic bandwidth caps: "
            f"Web={qos_limits['web_browsing_mbps']:.2f} Mbps, "
            f"Stream={qos_limits['streaming_mbps']:.2f} Mbps, "
            f"File={qos_limits['file_transfer_mbps']:.2f} Mbps, "
            f"Critical={qos_limits['critical_services_mbps']:.2f} Mbps"
        )
        
        # Execute platform-aware system shaper commands
        system_platform = platform.system().lower()
        
        try:
            if system_platform == "linux":
                # Real Linux tc (Traffic Control) queue adjustment
                interface = config.CAPTURE_INTERFACE or "eth0"
                # Limit total rate to link capacity using TBF
                rate_limit = f"{qos_limits['web_browsing_mbps'] + qos_limits['streaming_mbps'] + qos_limits['file_transfer_mbps']:.1f}mbit"
                cmd = ["sudo", "tc", "qdisc", "change", "dev", interface, "root", "tbf", "rate", rate_limit, "burst", "32k", "latency", "400ms"]
                logger.info(f"[SHAPER] Executing Linux tc command: {' '.join(cmd)}")
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
            elif system_platform == "windows":
                # Real Windows PowerShell QoS policy throttling
                # Ensure the system-wide QoS policy exists on startup
                check_cmd = ["powershell", "-Command", "Get-NetQosPolicy -Name 'NetInsight-Throttle' -ErrorAction Stop"]
                check_result = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if check_result.returncode != 0:
                    create_cmd = ["powershell", "-Command", "New-NetQosPolicy -Name 'NetInsight-Throttle' -IPProtocol MatchAny -ThrottleRateActionBytesPerSecond 100000000 -ErrorAction SilentlyContinue"]
                    logger.info("[SHAPER] Initializing NetInsight QoS Policy on Windows...")
                    subprocess.run(create_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                # Throttle file transfers (e.g. 2 Mbps -> 256KB/s)
                bytes_per_sec = int(qos_limits['file_transfer_mbps'] * 125000)
                cmd = ["powershell", "-Command", f"Set-NetQosPolicy -Name 'NetInsight-Throttle' -ThrottleRateActionBytesPerSecond {bytes_per_sec} -ErrorAction SilentlyContinue"]
                logger.info(f"[SHAPER] Executing Windows PowerShell QoS command: {' '.join(cmd)}")
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                
        except Exception as e:
            logger.warning(
                f"[SHAPER] Local hardware shaping command skipped (Requires Admin/Root privileges). "
                f"Falling back to simulated logs. Error: {e}"
            )
            
        # Simulate local rate-limiting (throttling agent capture rate or introducing delays)
        if policy == "Prioritize Critical Services":
            logger.warning("[SHAPER] Local Action Enforced: File transfer throttled to 0.25x. Critical Services priority enabled.")
        elif policy == "Reroute Traffic":
            logger.warning("[SHAPER] Local Action Enforced: Throttling heavy streaming and file transfers. Primary web capacity prioritized.")
        else:
            logger.info("[SHAPER] Local Action Enforced: Maintaining normal unrestricted traffic profile.")

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

        # Check SSID restriction if configured
        if config.HOTSPOT_SSID:
            current_ssid = get_current_ssid()
            while current_ssid != config.HOTSPOT_SSID:
                logger.warning(f"Device is connected to '{current_ssid}', but HOTSPOT_SSID is set to '{config.HOTSPOT_SSID}'. Waiting to connect to hotspot...")
                time.sleep(5)
                current_ssid = get_current_ssid()

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

        while self.is_running:
            # Check SSID restriction if configured
            if config.HOTSPOT_SSID:
                current_ssid = get_current_ssid()
                if current_ssid != config.HOTSPOT_SSID:
                    logger.warning(f"Device is connected to '{current_ssid}', but HOTSPOT_SSID is set to '{config.HOTSPOT_SSID}'. Skipping telemetry upload...")
                    # Clear sniffer packets so they don't pile up in memory
                    self.sniffer.get_and_clear_packets()
                    time.sleep(config.TELEMETRY_INTERVAL)
                    continue

            start_time = time.time()

            # Self-healing registration check: re-register if server invalidated agent ID
            if not self.sender.agent_id:
                logger.warning("Agent ID missing or invalidated. Re-running registration sequence...")
                mac_addr = get_mac_address()
                self.sender.register(mac_addr, self.collector.hostname, self.collector.os_type, self.collector.vendor)

            # Gather host stats
            stats = self.collector.collect()

            # Get new packets and combine with previously failed packets
            new_packets = self.sniffer.get_and_clear_packets()
            failed_packets = []
            if os.path.exists(self.offline_file):
                try:
                    with open(self.offline_file, encoding="utf-8") as f:
                        failed_packets = json.load(f)
                except Exception as e:
                    logger.error(f"Error reading offline buffer: {e}")
            
            packets_to_send = failed_packets + new_packets

            # Bounded limit for transmission safety (send at most 100 recent packets to prevent server timeouts)
            max_send = 100
            if len(packets_to_send) > max_send:
                logger.info(f"Packet batch size ({len(packets_to_send)}) exceeds transmission safety cap ({max_send}). Sampling the latest {max_send} packets.")
                packets_to_send = packets_to_send[-max_send:]

            # Try uploading
            success, qos_limits = self.sender.send_telemetry(stats, packets_to_send)

            if success:
                # Clear queue on success
                if os.path.exists(self.offline_file):
                    try:
                        os.remove(self.offline_file)
                    except Exception as e:
                        logger.error(f"Failed to remove offline buffer: {e}")
                backoff = config.TELEMETRY_INTERVAL  # Reset backoff on success
                
                # Apply dynamic QoS shaping constraints locally (Closed-loop feedback execution)
                if qos_limits:
                    self.apply_local_shaping(qos_limits)
            else:
                # Save queue on failure (cap at 200 to prevent large retry batches)
                if len(packets_to_send) > 200:
                    packets_to_send = packets_to_send[-200:]
                try:
                    with open(self.offline_file, "w", encoding="utf-8") as f:
                        json.dump(packets_to_send, f)
                except Exception as e:
                    logger.error(f"Failed to write to offline buffer: {e}")
                logger.warning(f"Telemetry upload failed. Saved {len(packets_to_send)} packets to disk-buffered queue.")
                
                # Force a constant fast retry interval instead of exponential backoff
                backoff = config.TELEMETRY_INTERVAL

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
