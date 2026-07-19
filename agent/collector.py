import socket
import os
import platform
import psutil
from agent.logger import logger

class TelemetryCollector:
    """Queries hardware state metrics and network usage counts from the local host."""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_type = platform.system()
        self.vendor = platform.processor() or "Unknown"

    def get_primary_ip(self) -> str:
        """Finds the primary local IP address of the active routing adapter."""
        try:
            # Connect to an external address (doesn't send actual data) to discover local interface IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            try:
                return socket.gethostbyname(self.hostname)
            except Exception:
                return "127.0.0.1"

    def get_active_connections(self) -> int:
        """Counts active TCP/UDP internet connections."""
        try:
            connections = psutil.net_connections(kind="inet")
            # Count connections in ESTABLISHED or LISTEN states
            active = [c for c in connections if c.status in ("ESTABLISHED", "LISTEN")]
            return len(active)
        except psutil.AccessDenied:
            logger.warning("Access denied when reading psutil net_connections. Falling back to established sockets count.")
            # Fallback estimation if not running with high privileges
            return len(psutil.net_connections(kind="tcp"))
        except Exception as e:
            logger.error(f"Error querying active connections: {e}")
            return 0

    def collect(self) -> dict:
        """Aggregates all host-level telemetry data into a serializable payload."""
        try:
            # Memory details
            mem = psutil.virtual_memory()
            
            # Disk details
            try:
                disk = psutil.disk_usage("/")
                disk_usage = disk.percent
            except Exception:
                try:
                    disk = psutil.disk_usage("C:\\" if os.name == "nt" else "/")
                    disk_usage = disk.percent
                except Exception:
                    disk_usage = 0.0

            # Net counters
            net_io = psutil.net_io_counters()

            payload = {
                "hostname": self.hostname,
                "ip_address": self.get_primary_ip(),
                "device_type": f"{self.os_type} {platform.release()}",
                "vendor": self.vendor,
                "cpu_usage": float(psutil.cpu_percent(interval=None)),
                "memory_usage": float(mem.percent),
                "disk_usage": float(disk_usage),
                "bytes_sent": int(net_io.bytes_sent),
                "bytes_recv": int(net_io.bytes_recv),
                "active_connections": int(self.get_active_connections())
            }
            return payload
        except Exception as e:
            logger.error(f"Failed to collect telemetry: {e}", exc_info=True)
            return {}
