import uuid
import psutil
from agent.logger import logger

def get_mac_address() -> str:
    """Discovers the physical MAC address of the active network interface."""
    try:
        # Loop through network interfaces
        for interface_name, addrs in psutil.net_if_addrs().items():
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
        mac_str = ":".join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2))
        return mac_str.lower()
    except Exception as e:
        logger.error(f"Fallback getnode MAC discovery failed: {e}")
        return "00:00:00:00:00:00"
