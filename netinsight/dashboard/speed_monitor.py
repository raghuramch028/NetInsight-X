import logging
import os
import threading
import time

import requests
from django.conf import settings

logger = logging.getLogger("netinsight.speed_monitor")

# Thread-safe global variable for dynamic capacity (initialized from settings)
_CAPACITY_LOCK = threading.Lock()
_CURRENT_CAPACITY = getattr(settings, "LINK_CAPACITY", 100000000.0)

def get_current_capacity() -> float:
    """Thread-safe getter for current dynamic link capacity."""
    with _CAPACITY_LOCK:
        return float(_CURRENT_CAPACITY)

def set_current_capacity(val: float) -> None:
    """Thread-safe setter for current dynamic link capacity."""
    global _CURRENT_CAPACITY
    with _CAPACITY_LOCK:
        _CURRENT_CAPACITY = float(val)

def run_speed_test():
    """Measures dynamic link capacity using configured external speed tests or local telemetry heuristics."""
    enable_external = getattr(settings, "NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST", False)
    if not enable_external:
        _run_telemetry_fallback("External speed test disabled (NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST=False).")
        return

    url = "https://speed.cloudflare.com/__down?bytes=10000000"
    try:
        start_time = time.perf_counter()
        # Stream download to track bytes chunk-by-chunk and allow early time cutoff
        response = requests.get(url, stream=True, timeout=(5, 10))

        if response.status_code == 200:
            total_bytes = 0
            # Read in 64KB chunks
            for chunk in response.iter_content(chunk_size=65536):
                total_bytes += len(chunk)
                elapsed = time.perf_counter() - start_time
                # Cap the speed test duration at 8.0 seconds max to save data on slow links
                if elapsed >= 8.0:
                    break

            elapsed = time.perf_counter() - start_time
            if elapsed > 0 and total_bytes > 0:
                speed_bps = (total_bytes * 8) / elapsed

                # Clamp between 2.0 Mbps and 100.0 Mbps for solver stability
                speed_bps = max(2000000.0, min(100000000.0, speed_bps))

                set_current_capacity(speed_bps)
                logger.info(f"[DYNAMIC CAPACITY] Google-style Speed test: {speed_bps / 1e6:.2f} Mbps (Downloaded {total_bytes/1e6:.2f} MB in {elapsed:.2f}s)")
                return
        raise Exception(f"HTTP status {response.status_code}")
    except Exception as e:
        _run_telemetry_fallback(f"Active speed test timed out/failed ({e}).")

def get_live_hardware_link_speed() -> float:
    """Queries OS network interface adapters to detect live link speed (in bps)."""
    try:
        import psutil
        stats = psutil.net_if_stats()
        active_speeds = []
        for name, iface in stats.items():
            if iface.isup and iface.speed > 0 and "loopback" not in name.lower():
                active_speeds.append((name, float(iface.speed) * 1_000_000.0))

        if active_speeds:
            # Prefer active Wi-Fi or primary interface speed
            wifi_speeds = [s[1] for s in active_speeds if "wifi" in s[0].lower() or "wlan" in s[0].lower()]
            if wifi_speeds:
                return wifi_speeds[0]
            return max(s[1] for s in active_speeds)
    except Exception as e:
        logger.debug(f"Hardware link speed query error: {e}")
    return float(getattr(settings, "LINK_CAPACITY", 100_000_000.0))


def _run_telemetry_fallback(reason: str):
    """Calculates capacity from recent telemetry throughput or live hardware interface speed."""
    logger.info(f"[SPEED MONITOR] {reason} Checking live hardware link speed...")
    try:
        import django.db

        from netinsight.dashboard.models import MetricRecord
        try:
            records = MetricRecord.objects.all().order_by("-timestamp")[:40]
            if records.exists():
                max_throughput = max(r.throughput for r in records)
                if max_throughput > 100000.0:
                    speed_bps = max_throughput * 1.25
                    speed_bps = max(2000000.0, min(1000000000.0, speed_bps))
                    set_current_capacity(speed_bps)
                    logger.info(f"[DYNAMIC CAPACITY] Telemetry Live Monitor: Set capacity to {speed_bps / 1e6:.2f} Mbps from active traffic.")
                else:
                    hw_speed = get_live_hardware_link_speed()
                    set_current_capacity(hw_speed)
                    logger.info(f"[DYNAMIC CAPACITY] Live Interface Detection: Detected hardware link capacity {hw_speed / 1e6:.1f} Mbps.")
            else:
                hw_speed = get_live_hardware_link_speed()
                set_current_capacity(hw_speed)
                logger.info(f"[DYNAMIC CAPACITY] Live Interface Detection: Detected hardware link capacity {hw_speed / 1e6:.1f} Mbps.")
        finally:
            django.db.close_old_connections()
    except Exception as fallback_err:
        logger.error(f"[SPEED MONITOR] Telemetry fallback failed: {fallback_err}")

def speed_monitor_loop():
    """Infinite loop executing speed tests every 30 seconds."""
    # Allow Django server to complete boot sequence
    time.sleep(5)
    run_speed_test()
    while True:
        time.sleep(int(os.environ.get("NETINSIGHT_SPEEDTEST_INTERVAL", "300")))
        run_speed_test()

def start_speed_monitor():
    """Launches the background daemon thread."""
    logger.info("Initializing dynamic network capacity speed monitor...")
    t = threading.Thread(target=speed_monitor_loop, daemon=True)
    t.start()
