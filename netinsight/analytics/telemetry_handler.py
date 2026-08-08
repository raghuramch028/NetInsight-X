import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.db import close_old_connections
from django.db.models import Count, Sum
from django.utils import timezone

from netinsight.analytics.flow_builder import prepare_packet_record
from netinsight.dashboard.models import (
    Agent,
    FlowRecord,
    MetricRecord,
    PacketRecord,
    ThreatHistory,
)

logger = logging.getLogger(__name__)

# Bounded thread pool prevents unbounded thread creation under high agent load
_telemetry_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="telemetry")

_MAX_INFLIGHT_TELEMETRY_TASKS = int(os.environ.get("NETINSIGHT_MAX_INFLIGHT_TELEMETRY_TASKS", "16"))
_telemetry_inflight_semaphore = threading.BoundedSemaphore(_MAX_INFLIGHT_TELEMETRY_TASKS)


def handle_telemetry_ingestion(agent: Agent, stats_data: dict, packets_list: list[dict]) -> None:
    """Orchestrates system telemetry ingestion and metrics aggregation."""
    try:
        # 1. Update Agent stats synchronously with numerical bounds clamping
        agent.cpu_usage = max(0.0, min(100.0, float(stats_data.get("cpu_usage", 0.0))))
        agent.memory_usage = max(0.0, min(100.0, float(stats_data.get("memory_usage", 0.0))))
        agent.disk_usage = max(0.0, min(100.0, float(stats_data.get("disk_usage", 0.0))))
        agent.bytes_sent = max(0, int(stats_data.get("bytes_sent", 0)))
        agent.bytes_recv = max(0, int(stats_data.get("bytes_recv", 0)))
        agent.active_connections = max(0, int(stats_data.get("active_connections", 0)))
        agent.last_seen = timezone.now()

        for attempt in range(5):
            try:
                agent.save()
                break
            except Exception as ex:
                if "locked" in str(ex).lower() and attempt < 4:
                    time.sleep(0.05 * (attempt + 1))
                    close_old_connections()
                else:
                    raise

        # 2. Spin off heavy queries and analysis to a background thread
        if _telemetry_inflight_semaphore.acquire(blocking=False):
            _telemetry_pool.submit(_async_telemetry_worker, agent.id, stats_data, packets_list)
        else:
            logger.warning(
                f"Telemetry processing backlog full ({_MAX_INFLIGHT_TELEMETRY_TASKS} tasks in flight); "
                f"skipping heavy analytics for agent {agent.id}."
            )

    except Exception as e:
        logger.error(f"Error handling telemetry payload: {e}", exc_info=True)


def _async_telemetry_worker(agent_id: int, stats_data: dict, packets_list: list[dict]) -> None:
    """Handles heavy processing tasks asynchronously without blocking client uploads."""
    close_old_connections()
    try:
        for attempt in range(5):
            try:
                _execute_async_telemetry_worker(agent_id, stats_data, packets_list)
                break
            except Exception as ex:
                if "locked" in str(ex).lower() and attempt < 4:
                    time.sleep(0.05 * (attempt + 1))
                    close_old_connections()
                else:
                    logger.error(f"Error in async telemetry worker thread: {ex}", exc_info=True)
                    break
            finally:
                close_old_connections()
    finally:
        _telemetry_inflight_semaphore.release()


def _execute_async_telemetry_worker(agent_id: int, stats_data: dict, packets_list: list[dict]) -> None:
    try:
        agent = Agent.objects.get(id=agent_id)
    except Agent.DoesNotExist:
        return

    now_ts = time.time()

    # A. Process and Classify all incoming packets
    packet_objects = []
    for pkt in packets_list:
        pkt_obj = prepare_packet_record(agent, pkt)
        if pkt_obj:
            packet_objects.append(pkt_obj)

    if packet_objects:
        PacketRecord.objects.bulk_create(packet_objects, ignore_conflicts=True)

    # B. Calculate Server-Side Network-Wide Metrics (window: last 10 seconds)
    window_start = now_ts - 10.0
    active_packets = PacketRecord.objects.filter(timestamp__gte=window_start)

    packet_count = active_packets.count()
    total_bytes = active_packets.aggregate(total_bytes=Sum("size"))["total_bytes"] or 0

    throughput = (total_bytes * 8.0) / 10.0
    packet_rate = float(packet_count) / 10.0

    from netinsight.config import settings
    link_capacity = getattr(settings, "LINK_CAPACITY", 100_000_000.0)
    bandwidth_util = (throughput / link_capacity) * 100.0

    _DEFAULT_LATENCY_SECONDS = 0.015
    _MAX_PLAUSIBLE_LATENCY_SECONDS = 10.0
    reported_rtt = stats_data.get("rtt_seconds")
    try:
        reported_rtt = float(reported_rtt) if reported_rtt is not None else None
    except (TypeError, ValueError):
        reported_rtt = None
    if reported_rtt is not None and 0.0 <= reported_rtt <= _MAX_PLAUSIBLE_LATENCY_SECONDS:
        latency = reported_rtt
    else:
        latency = _DEFAULT_LATENCY_SECONDS

    # Calculate packet loss from TCP sequence retransmissions
    tcp_packets = active_packets.filter(protocol__iexact="TCP")
    total_tcp = tcp_packets.count()
    packet_loss = 0.0
    if total_tcp > 0:
        tcp_with_seq = tcp_packets.exclude(tcp_seq__isnull=True)
        if tcp_with_seq.exists():
            duplicate_groups = (
                tcp_with_seq.values("src_ip", "dst_ip", "src_port", "dst_port", "tcp_seq")
                .annotate(occurrences=Count("id"))
                .filter(occurrences__gt=1)
            )
            retransmission_like_packets = sum(max(0, g["occurrences"] - 1) for g in duplicate_groups)
            packet_loss = (float(retransmission_like_packets) / max(1, total_tcp)) * 100.0

    # Commit calculated metrics to MetricRecord
    MetricRecord.objects.create(
        timestamp=now_ts,
        throughput=throughput,
        packet_rate=packet_rate,
        bandwidth_util=bandwidth_util,
        latency=latency,
        packet_loss=packet_loss
    )


_PRUNE_INTERVAL_SECONDS = float(os.environ.get("NETINSIGHT_PRUNE_INTERVAL_SECONDS", "60"))


def _prune_stale_records() -> None:
    """Deletes stale records across all tables."""
    close_old_connections()
    try:
        now_ts = time.time()
        prune_cutoff = now_ts - 600.0
        PacketRecord.objects.filter(timestamp__lt=prune_cutoff).delete()

        retention_cutoff = now_ts - 86400.0  # 24 hours
        FlowRecord.objects.filter(end_time__lt=retention_cutoff).delete()
        MetricRecord.objects.filter(timestamp__lt=retention_cutoff).delete()
        retention_cutoff_dt = timezone.now() - timedelta(hours=24)
        ThreatHistory.objects.filter(timestamp__lt=retention_cutoff_dt).delete()
    except Exception as e:
        logger.error(f"Error during periodic DB pruning: {e}", exc_info=True)
    finally:
        close_old_connections()


def _periodic_pruning_loop() -> None:
    while True:
        time.sleep(_PRUNE_INTERVAL_SECONDS)
        _prune_stale_records()


def start_periodic_pruner() -> None:
    """Starts the background pruning thread."""
    from netinsight.dashboard.process_lock import acquire_singleton_lock

    if not acquire_singleton_lock("db_pruner"):
        logger.info("Another process already owns the DB pruning task; skipping in this process.")
        return
    t = threading.Thread(target=_periodic_pruning_loop, daemon=True, name="DBPruner")
    t.start()
    logger.info(f"Started periodic DB pruning background thread (interval={_PRUNE_INTERVAL_SECONDS:.0f}s).")


def drain_telemetry_pool(timeout: float = 5.0) -> None:
    """Waits for all currently in-flight async telemetry worker tasks to complete."""
    start = time.time()
    while time.time() - start < timeout:
        if _telemetry_inflight_semaphore._value == _MAX_INFLIGHT_TELEMETRY_TASKS:
            break
        time.sleep(0.05)
    close_old_connections()
