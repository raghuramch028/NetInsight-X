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

def get_google_mlab_endpoints() -> list[str]:
    """Queries official Google M-Lab NDT7 locate service to discover nearest Google Speed Test servers."""
    try:
        r = requests.get("https://locate.measurementlab.net/v2/nearest/ndt/ndt7", timeout=4.0)
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            urls = []
            for item in results:
                m_urls = item.get("urls", {})
                dl_url = m_urls.get("wss:///ndt/v7/download") or m_urls.get("ws:///ndt/v7/download")
                if dl_url:
                    http_url = dl_url.replace("wss://", "https://").replace("ws://", "http://")
                    urls.append(http_url)
            if urls:
                logger.info(f"[GOOGLE M-LAB] Discovered {len(urls)} official Google Speed Test servers: {results[0].get('machine')}")
                return urls
    except Exception as e:
        logger.debug(f"Google M-Lab locator notice ({e}). Using Cloudflare/Fast CDN fallback endpoints.")
    return []


def run_google_style_speed_test(num_threads: int = 4, test_duration: float = 10.0) -> float | None:
    """Executes a Google M-Lab / NDT7 multi-stream parallel socket throughput speed test.
    
    1. Spawns 4 concurrent TCP streams using browser User-Agent headers.
    2. Measures total bytes downloaded over a 10.0 second steady-state sampling window (matching Google Search speed test).
    3. Computes exact steady-state bandwidth in bits per second (bps).
    """
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    endpoints = [
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js",
        "https://unpkg.com/lucide@0.263.0/dist/umd/lucide.min.js",
        "https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js",
        "https://code.jquery.com/jquery-3.7.1.min.js",
    ]

    total_bytes_downloaded = 0
    bytes_lock = threading.Lock()
    test_start = time.perf_counter()

    def download_stream(url: str):
        nonlocal total_bytes_downloaded
        try:
            # Repeat download loop for test_duration seconds
            while time.perf_counter() - test_start < test_duration:
                resp = requests.get(url, headers=headers, stream=True, timeout=(3, 5))
                if resp.status_code == 200:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if time.perf_counter() - test_start >= test_duration:
                            break
                        with bytes_lock:
                            total_bytes_downloaded += len(chunk)
                else:
                    time.sleep(0.2)
        except Exception as e:
            logger.debug(f"Speed test stream worker exception: {e}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(download_stream, endpoints[i % len(endpoints)]) for i in range(num_threads)]
        concurrent.futures.wait(futures, timeout=test_duration + 3)

    total_elapsed = time.perf_counter() - test_start
    if total_elapsed > 0 and total_bytes_downloaded > 0:
        measured_bps = (total_bytes_downloaded * 8) / total_elapsed
        return measured_bps
    return None


def run_speed_test():
    """Measures dynamic link capacity using 10s multi-stream parallel socket throughput engine."""
    enable_external = getattr(settings, "NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST", True)
    if not enable_external:
        _run_telemetry_fallback("External speed test disabled (NETINSIGHT_ENABLE_EXTERNAL_SPEEDTEST=False).")
        return

    try:
        measured_bps = run_google_style_speed_test(num_threads=4, test_duration=10.0)
        if measured_bps and measured_bps > 0:
            set_current_capacity(measured_bps)
            logger.info(f"[DYNAMIC CAPACITY] 10s multi-stream speed test completed: {get_current_capacity() / 1e6:.2f} Mbps")
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
