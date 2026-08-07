"""Synthetic telemetry generator for NETINSIGHT_DEMO_MODE.

Previously this ~90-line generator (and its ensure_monitor_started() guard) was copy-pasted
verbatim into api_views.py, page_views.py, and report_views.py, each with its own independent
_demo_thread_started flag. Only page_views.py's copy was ever actually invoked — the other two
were dead code — but the duplication meant any future edit had to be made in three places to
stay consistent. Consolidated here as the single source of truth.

Also guarded by the cross-process singleton lock (process_lock.py): under a multi-worker
gunicorn deployment, every worker process previously started its own independent generator
thread, multiplying synthetic packets/metrics/state rows by the worker count and risking
MetricRecord/StateHistory primary-key (float timestamp) collisions across workers.
"""
import logging
import random
import threading
import time as _time

from django.db import close_old_connections
from django.utils import timezone

from netinsight.config import settings
from netinsight.dashboard.models import Agent, MetricRecord, PacketRecord, StateHistory
from netinsight.dashboard.process_lock import acquire_singleton_lock

logger = logging.getLogger(__name__)

_demo_lock = threading.Lock()
_demo_thread_started = False


def _demo_telemetry_generator():
    """Background thread generating synthetic telemetry data for demo/demonstration mode."""
    close_old_connections()
    try:
        _time.sleep(3)  # Wait for Django to fully boot
        demo_agent, _ = Agent.objects.get_or_create(
            mac_address="de:mo:00:00:00:01",
            defaults={
                "hostname": "Demo-Agent-1",
                "device_type": "Demo Node",
                "vendor": "NetInsight Demo",
                "ip_address": "192.168.1.100"
            }
        )
        states = ["Normal", "Normal", "Normal", "Busy", "Busy", "Congested"]
        protocols = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]
        while True:
            close_old_connections()
            now_ts = _time.time()
            demo_agent.cpu_usage = round(random.uniform(15, 65), 1)
            demo_agent.memory_usage = round(random.uniform(30, 75), 1)
            demo_agent.disk_usage = round(random.uniform(20, 50), 1)
            demo_agent.active_connections = random.randint(5, 40)
            demo_agent.bytes_sent = random.randint(100000, 5000000)
            demo_agent.bytes_recv = random.randint(500000, 15000000)
            demo_agent.last_seen = timezone.now()
            demo_agent.save()
            # Generate synthetic packets
            for _ in range(random.randint(3, 8)):
                PacketRecord.objects.create(
                    src_ip=f"192.168.1.{random.randint(2, 254)}",
                    dst_ip=f"10.0.0.{random.randint(1, 50)}",
                    src_port=random.randint(1024, 65535),
                    dst_port=random.choice([80, 443, 53, 22, 8080]),
                    protocol=random.choice(protocols),
                    size=random.randint(64, 1500),
                    timestamp=now_ts,
                    ttl=random.choice([64, 128]),
                    agent=demo_agent
                )
            # Generate synthetic metric
            throughput = random.uniform(1e6, 8e6)
            MetricRecord.objects.create(
                timestamp=now_ts,
                throughput=throughput,
                packet_rate=random.uniform(50, 300),
                bandwidth_util=random.uniform(5, 60),
                latency=random.uniform(0.005, 0.080),
                packet_loss=random.uniform(0, 2.0)
            )
            # Generate synthetic state
            StateHistory.objects.create(
                timestamp=now_ts,
                network_state=random.choice(states),
                bandwidth_utilization=random.uniform(0.05, 0.60),
                packet_loss=random.uniform(0, 0.02),
                latency=random.uniform(0.005, 0.080)
            )
            # Prune old demo data (keep last 5 minutes)
            cutoff = now_ts - 300
            PacketRecord.objects.filter(timestamp__lt=cutoff, agent=demo_agent).delete()
            _time.sleep(3)
    except Exception as e:
        logger.error(f"Demo telemetry generator error: {e}", exc_info=True)
    finally:
        close_old_connections()


def ensure_monitor_started():
    """Starts the demo telemetry generator if DEMO_MODE is active. Thread-safe check-and-set
    within this process, plus a cross-process lock so only one worker process runs it."""
    global _demo_thread_started
    if not settings.DEMO_MODE or _demo_thread_started:
        return
    with _demo_lock:
        if _demo_thread_started:
            return
        if not acquire_singleton_lock("demo_generator"):
            logger.info("Another process already owns the demo-telemetry generator; skipping in this process.")
            _demo_thread_started = True  # Don't retry the cross-process lock on every request.
            return
        _demo_thread_started = True
        t = threading.Thread(target=_demo_telemetry_generator, daemon=True, name="DemoTelemetryGen")
        t.start()
        logger.info("[DEMO MODE] Synthetic telemetry generator started.")
