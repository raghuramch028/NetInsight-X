import os
import platform
import socket
import subprocess

import psutil

from agent.logger import logger


def apply_windows_qos_caps(enforced_qos: dict) -> bool:
    """Applies kernel-level bandwidth rate caps using Windows NetQosPolicy PowerShell cmdlets."""
    if platform.system().lower() != "windows":
        return False
    try:
        crit_mbps = float(enforced_qos.get("critical_services_mbps", 40.0))
        bytes_per_sec = int(crit_mbps * 125000)

        # Check if policy exists
        check_cmd = ["powershell", "-Command", "Get-NetQosPolicy -Name 'NetInsight-Critical' -ErrorAction Stop"]
        res = subprocess.run(check_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            create_cmd = [
                "powershell",
                "-Command",
                f"New-NetQosPolicy -Name 'NetInsight-Critical' -IPProtocol MatchAny -ThrottleRateActionBytesPerSecond {bytes_per_sec} -ErrorAction SilentlyContinue"
            ]
            subprocess.run(create_cmd, capture_output=True, timeout=5)
        else:
            set_cmd = [
                "powershell",
                "-Command",
                f"Set-NetQosPolicy -Name 'NetInsight-Critical' -ThrottleRateActionBytesPerSecond {bytes_per_sec} -ErrorAction SilentlyContinue"
            ]
            subprocess.run(set_cmd, capture_output=True, timeout=5)

        logger.info(f"Successfully configured Windows NetQosPolicy (Critical Services: {crit_mbps:.1f} Mbps / {bytes_per_sec} Bps)")
        return True
    except Exception as e:
        logger.warning(f"Windows NetQosPolicy execution notice: {e}")
        return False


class TelemetryCollector:
    """Queries hardware state metrics and network usage counts from the local host."""

    def __init__(self):
        self.hostname = socket.gethostname()
        self.os_type = platform.system()
        self.vendor = platform.processor() or "Unknown"

    def get_primary_ip(self) -> str:
        """Finds the primary local IP address of the active routing adapter."""
        try:
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
            active = [c for c in connections if c.status in ("ESTABLISHED", "LISTEN")]
            return len(active)
        except (psutil.AccessDenied, Exception) as e:
            logger.warning(f"Access denied or error querying net_connections ({e}). Falling back to process count.")
            try:
                return len(psutil.pids())
            except Exception:
                return 0

    def collect(self) -> dict:
        """Aggregates all host-level telemetry data into a serializable payload."""
        try:
            mem = psutil.virtual_memory()

            try:
                disk = psutil.disk_usage("/")
                disk_usage = disk.percent
            except Exception:
                try:
                    disk = psutil.disk_usage("C:\\" if os.name == "nt" else "/")
                    disk_usage = disk.percent
                except Exception:
                    disk_usage = 0.0

            net_io = psutil.net_io_counters()

            payload = {
                "hostname": self.hostname,
                "ip_address": self.get_primary_ip(),
                "device_type": f"{self.os_type} {platform.release()}",
                "vendor": self.vendor,
                "cpu_usage": float(psutil.cpu_percent(interval=0.1)),
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
