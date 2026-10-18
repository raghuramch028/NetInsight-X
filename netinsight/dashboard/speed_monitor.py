import logging
import os
import threading
import time

import requests
from django.conf import settings

logger = logging.getLogger("netinsight.speed_monitor")

# Thread-safe global variable for dynamic capacity (initialized from settings, default 100 Mbps)
_CAPACITY_LOCK = threading.Lock()
_CURRENT_CAPACITY = getattr(settings, "LINK_CAPACITY", 100000000.0)
_CAPACITY_SOURCE = "configured fallback"

def get_current_capacity() -> float:
    """Thread-safe getter for current measured internet download capacity (in bps)."""
    with _CAPACITY_LOCK:
        return float(_CURRENT_CAPACITY)

def get_current_capacity_source() -> str:
    """Return whether capacity is measured or using the configured fallback."""
    with _CAPACITY_LOCK:
        return _CAPACITY_SOURCE

def set_current_capacity(val: float, source: str = "internet download test") -> None:
    """Set measured internet capacity (bps), with a minimum 1 Mbps solver floor."""
    global _CURRENT_CAPACITY, _CAPACITY_SOURCE
    clamped_val = max(1000000.0, float(val))
    with _CAPACITY_LOCK:
        _CURRENT_CAPACITY = clamped_val
        _CAPACITY_SOURCE = source



def get_os_link_speed_bps() -> float | None:
    """Reads physical link speed from the OS interface that actually has internet connectivity.

    Detects the active internet interface by checking which IP routes to 8.8.8.8,
    then looks up that interface's link speed. This prevents VirtualBox/VMware
    host-only adapters (1000 Mbps, no internet) from overriding the real Wi-Fi.

    Returns link speed in bits per second, or None if unavailable.
    """
    try:
        import socket
        import psutil

        # 1. Find which local IP routes to the internet
        active_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            active_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()

        # 2. If we found an active IP, find which interface owns it
        if active_ip:
            for iface_name, iface_addrs in addrs.items():
                iface_ips = [a.address for a in iface_addrs if a.family == socket.AF_INET]
                if active_ip in iface_ips:
                    iface_stats = stats.get(iface_name)
                    if iface_stats and iface_stats.isup and iface_stats.speed > 0:
                        speed_mbps = iface_stats.speed
                        logger.info(f"[SPEED MONITOR] Active internet interface '{iface_name}': {speed_mbps} Mbps")
                        return speed_mbps * 1_000_000.0
                    break

        # 3. Fallback: pick the best non-loopback, non-virtual interface
        best_speed = None
        for iface_name, iface_stats in stats.items():
            if not iface_stats.isup:
                continue
            iface_lower = iface_name.lower()
            if 'loopback' in iface_lower or 'pseudo' in iface_lower or iface_lower == 'lo':
                continue
            speed_mbps = iface_stats.speed
            if speed_mbps and speed_mbps > 0:
                if best_speed is None or speed_mbps > best_speed:
                    best_speed = speed_mbps
                    logger.debug(f"[SPEED MONITOR] Fallback interface '{iface_name}': {speed_mbps} Mbps")
        if best_speed:
            return best_speed * 1_000_000.0
    except Exception as e:
        logger.debug(f"[SPEED MONITOR] Could not read OS link speed: {e}")
    return None


def run_active_throughput_test() -> float | None:
    """Measures internet download throughput with one bounded HTTP download."""
    test_bytes = min(max(int(os.environ.get("NETINSIGHT_SPEEDTEST_BYTES", "1000000")), 262144), 10000000)
    url = f"https://speed.cloudflare.com/__down?bytes={test_bytes}"
    headers = {
        "Cache-Control": "no-cache",
        "User-Agent": "NetInsight-X capacity monitor",
    }
    start = time.perf_counter()
    downloaded_bytes = 0

    with requests.get(url, headers=headers, stream=True, timeout=(5, 30)) as response:
        response.raise_for_status()
        for chunk in response.iter_content(chunk_size=65536):
            downloaded_bytes += len(chunk)

    elapsed = time.perf_counter() - start
    if downloaded_bytes < test_bytes or elapsed <= 0:
        return None
    return (downloaded_bytes * 8.0) / elapsed


def run_speed_test():
    """Measures internet download capacity rather than the local adapter link rate."""
    enable_external = getattr(settings, "NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST", True)
    if not enable_external:
        logger.info("[SPEED MONITOR] Internet speed test disabled; keeping configured or last measured capacity.")
        return

    try:
        measured_bps = run_active_throughput_test()
        if measured_bps and measured_bps > 0:
            set_current_capacity(measured_bps)
            logger.info(f"[INTERNET CAPACITY] Download throughput measured at {get_current_capacity() / 1e6:.2f} Mbps")
            return
        logger.warning("[SPEED MONITOR] Internet download test returned incomplete data; keeping previous capacity.")
    except Exception as e:
        logger.warning(f"[SPEED MONITOR] Internet download test failed; keeping previous capacity: {e}")

def speed_monitor_loop():
    """Refresh internet download capacity periodically."""
    run_speed_test()
    interval = max(60, int(os.environ.get("NETINSIGHT_SPEEDTEST_INTERVAL", "900")))
    while True:
        time.sleep(interval)
        run_speed_test()

def start_speed_monitor():
    """Launches the background daemon thread immediately, guarded by a cross-process singleton lock."""
    from netinsight.dashboard.process_lock import acquire_singleton_lock

    if not acquire_singleton_lock("speed_monitor"):
        logger.info("Another process already owns the speed-monitor task; skipping in this process.")
        return

    logger.info("Initializing dynamic network capacity speed monitor...")
    t = threading.Thread(target=speed_monitor_loop, daemon=True)
    t.start()
