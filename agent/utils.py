import socket
import uuid

try:
    import psutil
except ImportError:
    psutil = None

from agent.logger import logger


def get_local_ip(server_host: str = "8.8.8.8", server_port: int = 80) -> str:
    """Discovers the machine's outbound LAN/hotspot IP address.

    Uses a UDP trick: opens a socket toward the server (no data sent) to let
    the OS pick the correct source interface, then reads the local address.
    Falls back to hostname resolution if that fails.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect((server_host, server_port))
            return s.getsockname()[0]
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "0.0.0.0"



def get_mac_address() -> str:
    """Discovers the physical MAC address of the active network interface."""
    if psutil is not None:
        try:
            # Loop through network interfaces
            for _interface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    # AF_LINK represents MAC addresses on Windows/macOS
                    # AF_PACKET represents MAC addresses on Linux
                    if addr.family in (psutil.AF_LINK, getattr(psutil, 'AF_PACKET', -1)):
                        mac = addr.address
                        # Filter out loopback interfaces
                        if mac and mac != "00:00:00:00:00:00" and not mac.startswith("00:00:00:00"):
                            return mac.replace("-", ":").lower()
        except Exception as e:
            logger.error(f"Error extracting MAC address from interfaces list: {e}")

    # Fallback to standard library uuid node discovery
    try:
        mac_num = uuid.getnode()
        mac_str = ":".join((f"{mac_num:012X}")[i:i+2] for i in range(0, 12, 2))
        return mac_str.lower()
    except Exception as e:
        logger.error(f"Fallback getnode MAC discovery failed: {e}")
        return "00:00:00:00:00:00"


def get_current_ssid() -> str:
    """Queries the OS to find the current active Wi-Fi SSID. Supports Windows, Linux, and macOS."""
    import platform
    import subprocess
    system = platform.system().lower()
    try:
        if system == "windows":
            output = subprocess.check_output(
                ["netsh", "wlan", "show", "interfaces"],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            for line in output.split("\n"):
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        return parts[1].strip()
        elif system == "linux":
            output = subprocess.check_output(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            for line in output.strip().split("\n"):
                if line.startswith("yes:"):
                    return line.split(":", 1)[1]
        elif system == "darwin":
            output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                stderr=subprocess.DEVNULL
            ).decode("utf-8", errors="ignore")
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("SSID:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None
