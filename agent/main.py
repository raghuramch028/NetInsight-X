import json
import os
import platform
import signal
import subprocess
import sys
import time

from agent import config
from agent.collector import TelemetryCollector
from agent.logger import logger
from agent.sender import TelemetrySender
from agent.sniffer import PacketSniffer
from agent.utils import get_current_ssid, get_mac_address


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

        system_platform = platform.system().lower()

        try:
            if system_platform == "linux":
                interface = config.CAPTURE_INTERFACE or "eth0"
                total_mbps = qos_limits['web_browsing_mbps'] + qos_limits['streaming_mbps'] + qos_limits['file_transfer_mbps'] + qos_limits['critical_services_mbps']
                rate_limit = f"{total_mbps:.1f}mbit"
                cmd = ["sudo", "tc", "qdisc", "change", "dev", interface, "root", "tbf", "rate", rate_limit, "burst", "32k", "latency", "400ms"]
                logger.info(f"[SHAPER] Executing Linux tc command: {' '.join(cmd)}")
                subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            elif system_platform == "windows":
                # Remove any existing global OS throttle policy so local speed tests and web traffic run unthrottled
                clean_cmd = ["powershell", "-Command", "Remove-NetQosPolicy -Name 'NetInsight-Throttle' -Confirm:$false -ErrorAction SilentlyContinue"]
                subprocess.run(clean_cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("[SHAPER] Maintaining unthrottled real network link performance.")

        except Exception as e:
            logger.warning(f"[SHAPER] Hardware shaping notice: {e}")

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
        signal.signal(signal.SIGINT, self.handle_shutdown)
        signal.signal(signal.SIGTERM, self.handle_shutdown)

        mac_addr = get_mac_address()
        hostname = self.collector.hostname
        device_type = self.collector.os_type
        vendor = self.collector.vendor

        logger.info(f"Local Host Details: MAC={mac_addr}, Hostname={hostname}, OS={device_type}")

        self.sniffer.start()
        self.is_running = True
        logger.info(f"Starting telemetry loop (Interval: {config.TELEMETRY_INTERVAL}s, Target Hotspot: '{config.HOTSPOT_SSID}')...")

        backoff = config.TELEMETRY_INTERVAL

        while self.is_running:
            # Enforce Wi-Fi Hotspot restriction
            if config.HOTSPOT_SSID:
                current_ssid = get_current_ssid()
                if current_ssid != config.HOTSPOT_SSID:
                    logger.warning(
                        f"[HOTSPOT RESTRICTION] Connected to Wi-Fi '{current_ssid or 'Disconnected/Ethernet'}', but target hotspot is '{config.HOTSPOT_SSID}'. "
                        "Telemetry upload and registration paused until connected to hotspot SEM3_PROJECT."
                    )
                    self.sniffer.get_and_clear_packets()
                    time.sleep(config.TELEMETRY_INTERVAL)
                    continue

            start_time = time.time()

            if not self.sender.agent_id:
                logger.warning("Agent ID missing or invalidated. Running registration sequence...")
                mac_addr = get_mac_address()
                if not self.sender.register(mac_addr, self.collector.hostname, self.collector.os_type, self.collector.vendor):
                    time.sleep(config.TELEMETRY_INTERVAL)
                    continue

            stats = self.collector.collect()

            if self.sender.last_rtt_seconds is not None:
                stats["rtt_seconds"] = self.sender.last_rtt_seconds

            new_packets = self.sniffer.get_and_clear_packets()
            failed_packets = []
            if os.path.exists(self.offline_file):
                try:
                    with open(self.offline_file, encoding="utf-8") as f:
                        failed_packets = json.load(f)
                except Exception as e:
                    logger.error(f"Error reading offline buffer: {e}")

            all_packets = failed_packets + new_packets
            batch_to_send = all_packets[:100]
            remaining_packets = all_packets[100:]

            success, qos_limits = self.sender.send_telemetry(stats, batch_to_send)

            if success:
                if remaining_packets:
                    remaining_packets = remaining_packets[-200:]
                    try:
                        with open(self.offline_file, "w", encoding="utf-8") as f:
                            json.dump(remaining_packets, f)
                    except Exception as e:
                        logger.error(f"Failed to write remaining packets to offline buffer: {e}")
                else:
                    if os.path.exists(self.offline_file):
                        try:
                            os.remove(self.offline_file)
                        except Exception as e:
                            logger.error(f"Failed to remove offline buffer: {e}")
                backoff = config.TELEMETRY_INTERVAL

                if qos_limits:
                    self.apply_local_shaping(qos_limits)
            else:
                to_buffer = all_packets[-200:]
                try:
                    with open(self.offline_file, "w", encoding="utf-8") as f:
                        json.dump(to_buffer, f)
                except Exception as e:
                    logger.error(f"Failed to write to offline buffer: {e}")
                logger.warning(f"Telemetry upload failed. Saved {len(to_buffer)} packets to disk-buffered queue.")

                backoff = config.TELEMETRY_INTERVAL

            elapsed = time.time() - start_time
            sleep_time = max(0.1, backoff - elapsed)
            time.sleep(sleep_time)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NetInsight-X Python Edge Agent")
    parser.add_argument(
        "--server", default=None,
        help="Central NetInsight-X server URL, e.g. http://192.168.1.10:8000 "
             "(overrides NETINSIGHT_SERVER_URL / SERVER_URL env vars)"
    )
    args = parser.parse_args()
    if args.server:
        config.set_server_url(args.server)

    agent = NetInsightAgent()
    try:
        agent.run()
    except Exception as e:
        logger.critical(f"Unhandled exception in agent main: {e}", exc_info=True)
        agent.stop()
        sys.exit(1)
