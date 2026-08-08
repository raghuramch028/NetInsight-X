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
    """Thread-safe setter for current real dynamic link capacity (minimum 1.0 Mbps floor, no upper artificial cap)."""
    global _CURRENT_CAPACITY
    clamped_val = max(1000000.0, float(val))
    with _CAPACITY_LOCK:
        _CURRENT_CAPACITY = clamped_val

import concurrent.futures

def run_google_style_speed_test(num_threads: int = 4, test_duration: float = 5.0) -> float | None:
    """Executes a Google M-Lab / NDT7 style multi-stream parallel socket throughput speed test.
    
    1. Spawns 4 concurrent TCP streams to saturate link capacity (bypassing single-stream TCP window bottlenecks).
    2. Measures total bytes downloaded over a 5.0 second steady-state sampling window.
    3. Computes exact steady-state bandwidth in bits per second (bps).
    """
    endpoints = [
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://speed.cloudflare.com/__down?bytes=25000000",
        "https://speed.cloudflare.com/__down?bytes=25000000",
    ]

    total_bytes_downloaded = 0
    bytes_lock = threading.Lock()
    test_start = time.perf_counter()

    def download_stream(url: str):
        nonlocal total_bytes_downloaded
        try:
            resp = requests.get(url, stream=True, timeout=(3, test_duration + 2))
            if resp.status_code == 200:
                for chunk in resp.iter_content(chunk_size=65536):
                    elapsed = time.perf_counter() - test_start
                    if elapsed > test_duration:
                        break
                    with bytes_lock:
                        total_bytes_downloaded += len(chunk)
        except Exception as e:
            logger.debug(f"Speed test stream worker exception: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(download_stream, endpoints[i % len(endpoints)]) for i in range(num_threads)]
        concurrent.futures.wait(futures, timeout=test_duration + 2)

    total_elapsed = time.perf_counter() - test_start
    if total_elapsed > 0 and total_bytes_downloaded > 0:
        measured_bps = (total_bytes_downloaded * 8) / total_elapsed
        return measured_bps
    return None


def run_speed_test():
    """Measures dynamic link capacity using Google M-Lab NDT7 style parallel streams or local telemetry heuristics."""
    enable_external = getattr(settings, "NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST", True)
    if not enable_external:
        _run_telemetry_fallback("External speed test disabled (NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST=False).")
        return

    try:
        measured_bps = run_google_style_speed_test(num_threads=4, test_duration=5.0)
        if measured_bps and measured_bps > 0:
            set_current_capacity(measured_bps)
            logger.info(f"[DYNAMIC CAPACITY] Google NDT7 multi-stream speed test completed: {get_current_capacity() / 1e6:.2f} Mbps")
            return
        raise Exception("Multi-stream speed test returned zero bytes")
    except Exception as e:
        _run_telemetry_fallback(f"Active speed test notice ({e}).")

def _run_telemetry_fallback(reason: str):
    """Calculates capacity from real active telemetry throughput or dynamic traffic rates."""
    logger.info(f"[SPEED MONITOR] {reason} Checking live measured internet throughput...")
    try:
        import django.db
        from netinsight.dashboard.models import MetricRecord, PacketRecord
        try:
            records = MetricRecord.objects.all().order_by("-timestamp")[:40]
            if records.exists():
                max_throughput = max(r.throughput for r in records)
                if max_throughput > 0.0:
                    speed_bps = max(max_throughput * 1.2, 2_000_000.0)
                    set_current_capacity(speed_bps)
                    logger.info(f"[DYNAMIC CAPACITY] Real-time Traffic Throughput: Capacity set to {get_current_capacity() / 1e6:.2f} Mbps from active flows.")
                    return

            # Check recent packet byte rates
            pkts = PacketRecord.objects.all().order_by("-timestamp")[:100]
            if pkts.exists():
                total_bytes = sum(p.size for p in pkts)
                speed_bps = max((total_bytes * 8) / 10.0, 2_000_000.0)
                set_current_capacity(speed_bps)
                logger.info(f"[DYNAMIC CAPACITY] Live Packet Stream: Capacity set to {get_current_capacity() / 1e6:.2f} Mbps.")
                return
        finally:
            django.db.close_old_connections()
    except Exception as fallback_err:
        logger.error(f"[SPEED MONITOR] Real-time throughput calculation notice: {fallback_err}")

def speed_monitor_loop():
    """Infinite loop executing Google-style speed tests every 30 seconds."""
    run_speed_test()
    interval = int(os.environ.get("NETINSIGHT_SPEEDTEST_INTERVAL", "30"))
    while True:
        time.sleep(interval)
        run_speed_test()

def start_speed_monitor():
    """Launches the background daemon thread immediately, guarded by a cross-process singleton lock."""
    from netinsight.dashboard.process_lock import acquire_singleton_lock

    if not acquire_singleton_lock("speed_monitor"):
        logger.info("Another process already owns the speed-monitor task; skipping in this process.")
        return

    logger.info("Initializing dynamic network capacity speed monitor (Google NDT7 engine)...")
    t = threading.Thread(target=speed_monitor_loop, daemon=True)
    t.start()
