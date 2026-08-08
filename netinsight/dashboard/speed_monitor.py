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

def get_current_capacity() -> float:
    """Thread-safe getter for current dynamic link capacity (in bps)."""
    with _CAPACITY_LOCK:
        return float(_CURRENT_CAPACITY)

def set_current_capacity(val: float) -> None:
    """Thread-safe setter for current dynamic link capacity (clamped between 2 Mbps and 100 Mbps)."""
    global _CURRENT_CAPACITY
    # Clamp capacity between 2.0 Mbps and 100.0 Mbps for baseline stability
    clamped_val = max(2000000.0, min(100000000.0, float(val)))
    with _CAPACITY_LOCK:
        _CURRENT_CAPACITY = clamped_val

def run_speed_test():
    """Measures dynamic link capacity using configured external speed tests or local telemetry heuristics."""
    enable_external = getattr(settings, "NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST", False)
    if not enable_external:
        _run_telemetry_fallback("External speed test disabled (NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST=False).")
        return

    url = "https://speed.cloudflare.com/__down?bytes=10000000"
    try:
        start_time = time.perf_counter()
        response = requests.get(url, stream=True, timeout=(5, 10))

        if response.status_code == 200:
            total_bytes = 0
            for chunk in response.iter_content(chunk_size=65536):
                total_bytes += len(chunk)
                elapsed = time.perf_counter() - start_time
                if elapsed >= 8.0:
                    break

            elapsed = time.perf_counter() - start_time
            if elapsed > 0 and total_bytes > 0:
                speed_bps = (total_bytes * 8) / elapsed
                set_current_capacity(speed_bps)
                logger.info(f"[DYNAMIC CAPACITY] Speed test completed: {get_current_capacity() / 1e6:.2f} Mbps (Downloaded {total_bytes/1e6:.2f} MB in {elapsed:.2f}s)")
                return
        raise Exception(f"HTTP status {response.status_code}")
    except Exception as e:
        _run_telemetry_fallback(f"Active speed test notice ({e}).")

def get_live_hardware_link_speed() -> float:
    """Queries OS network interface adapters to detect live link speed (clamped to 100 Mbps max)."""
    try:
        import psutil
        stats = psutil.net_if_stats()
        active_speeds = []
        for name, iface in stats.items():
            if iface.isup and iface.speed > 0 and "loopback" not in name.lower():
                active_speeds.append((name, float(iface.speed) * 1_000_000.0))

        if active_speeds:
            wifi_speeds = [s[1] for s in active_speeds if "wifi" in s[0].lower() or "wlan" in s[0].lower()]
            raw_speed = wifi_speeds[0] if wifi_speeds else max(s[1] for s in active_speeds)
            # Clamp hardware link speed to 100 Mbps max baseline for UI accuracy
            return min(100_000_000.0, raw_speed)
    except Exception as e:
        logger.debug(f"Hardware link speed query error: {e}")
    return float(getattr(settings, "LINK_CAPACITY", 100_000_000.0))

def _run_telemetry_fallback(reason: str):
    """Calculates capacity from recent telemetry throughput or live hardware interface speed."""
    logger.info(f"[SPEED MONITOR] {reason} Checking live link capacity...")
    try:
        import django.db
        from netinsight.dashboard.models import MetricRecord
        try:
            records = MetricRecord.objects.all().order_by("-timestamp")[:40]
            if records.exists():
                max_throughput = max(r.throughput for r in records)
                if max_throughput > 100000.0:
                    speed_bps = max_throughput * 1.25
                    set_current_capacity(speed_bps)
                    logger.info(f"[DYNAMIC CAPACITY] Telemetry Live Monitor: Set capacity to {get_current_capacity() / 1e6:.2f} Mbps from active traffic.")
                else:
                    hw_speed = get_live_hardware_link_speed()
                    set_current_capacity(hw_speed)
                    logger.info(f"[DYNAMIC CAPACITY] Live Interface Detection: Detected hardware link capacity {get_current_capacity() / 1e6:.1f} Mbps.")
            else:
                hw_speed = get_live_hardware_link_speed()
                set_current_capacity(hw_speed)
                logger.info(f"[DYNAMIC CAPACITY] Live Interface Detection: Detected hardware link capacity {get_current_capacity() / 1e6:.1f} Mbps.")
        finally:
            django.db.close_old_connections()
    except Exception as fallback_err:
        logger.error(f"[SPEED MONITOR] Telemetry fallback failed: {fallback_err}")
        set_current_capacity(100_000_000.0)

def speed_monitor_loop():
    """Infinite loop executing speed tests every 30 seconds."""
    time.sleep(3)
    run_speed_test()
    interval = int(os.environ.get("NETINSIGHT_SPEEDTEST_INTERVAL", "30"))
    while True:
        time.sleep(interval)
        run_speed_test()

def start_speed_monitor():
    """Launches the background daemon thread, guarded by a cross-process singleton lock."""
    from netinsight.dashboard.process_lock import acquire_singleton_lock

    if not acquire_singleton_lock("speed_monitor"):
        logger.info("Another process already owns the speed-monitor task; skipping in this process.")
        return

    logger.info("Initializing dynamic network capacity speed monitor (30s interval)...")
    t = threading.Thread(target=speed_monitor_loop, daemon=True)
    t.start()
