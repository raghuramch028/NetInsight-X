import time
import threading
import requests
import logging
from django.conf import settings

logger = logging.getLogger("netinsight.speed_monitor")

def run_speed_test():
    """Downloads a small static file to estimate current network link capacity dynamically."""
    # cloudflare-hosted file (~150 KB)
    url = "https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css"
    try:
        start_time = time.perf_counter()
        # 5-second timeout to prevent blocking during bad cellular signal
        response = requests.get(url, timeout=5)
        elapsed = time.perf_counter() - start_time
        
        if response.status_code == 200 and elapsed > 0:
            size_bits = len(response.content) * 8
            speed_bps = size_bits / elapsed
            
            # Clamp between 2.0 Mbps and 100.0 Mbps for solver stability
            speed_bps = max(2000000.0, min(100000000.0, speed_bps))
            
            # Dynamically update settings capacity in memory
            settings.LINK_CAPACITY = speed_bps
            logger.info(f"[DYNAMIC CAPACITY] Bandwidth capacity updated to {speed_bps / 1e6:.2f} Mbps based on active speed test.")
        else:
            logger.warning(f"[SPEED MONITOR] Speed test returned status {response.status_code}.")
    except Exception as e:
        logger.warning(f"[SPEED MONITOR] Active speed test timed out/failed ({e}). Maintaining capacity at {settings.LINK_CAPACITY / 1e6:.2f} Mbps.")

def speed_monitor_loop():
    """Infinite loop executing speed tests every 60 seconds."""
    # Allow Django server to complete boot sequence
    time.sleep(5)
    run_speed_test()
    while True:
        time.sleep(60)
        run_speed_test()

def start_speed_monitor():
    """Launches the background daemon thread."""
    logger.info("Initializing dynamic network capacity speed monitor...")
    t = threading.Thread(target=speed_monitor_loop, daemon=True)
    t.start()
