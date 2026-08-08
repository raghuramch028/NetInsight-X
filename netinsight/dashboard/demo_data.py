"""Synthetic telemetry generator for NETINSIGHT_DEMO_MODE."""
import logging
import random
import threading
import time as _time

from django.db import close_old_connections
from django.utils import timezone

from netinsight.config import settings
from netinsight.dashboard.models import Agent, MetricRecord, PacketRecord
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
            throughput = random.uniform(1e6, 8e6)
            MetricRecord.objects.create(
                timestamp=now_ts,
                throughput=throughput,
                packet_rate=random.uniform(50, 300),
                bandwidth_util=random.uniform(5, 60),
                latency=random.uniform(0.005, 0.080),
                packet_loss=random.uniform(0, 2.0)
            )
            cutoff = now_ts - 300
            PacketRecord.objects.filter(timestamp__lt=cutoff, agent=demo_agent).delete()
            _time.sleep(3)
    except Exception as e:
        logger.error(f"Demo telemetry generator error: {e}", exc_info=True)
    finally:
        close_old_connections()


def ensure_monitor_started():
    """Starts the demo telemetry generator if DEMO_MODE is active."""
    global _demo_thread_started
    if not settings.DEMO_MODE or _demo_thread_started:
        return
    with _demo_lock:
        if _demo_thread_started:
            return
        if not acquire_singleton_lock("demo_generator"):
            logger.info("Another process already owns the demo-telemetry generator; skipping in this process.")
            _demo_thread_started = True
            return
        _demo_thread_started = True
        t = threading.Thread(target=_demo_telemetry_generator, daemon=True, name="DemoTelemetryGen")
        t.start()
        logger.info("[DEMO MODE] Synthetic telemetry generator started.")
