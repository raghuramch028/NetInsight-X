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
    StateHistory,
    ThreatHistory,
)
from netinsight.prediction.hmm import get_shared_hmm

logger = logging.getLogger(__name__)
hmm_model = get_shared_hmm()

# Bounded thread pool prevents unbounded thread creation under high agent load
_telemetry_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="telemetry")

# Backpressure guard: previously handle_telemetry_ingestion() submitted to _telemetry_pool
# unconditionally, so a sustained overload (many agents, slow DB) grew an unbounded backlog of
# queued tasks with no visibility and ever-increasing processing lag. This bounds the number of
# in-flight async tasks; once the cap is hit, a tick's heavy enrichment (packet classification,
# metrics, HMM decode) is skipped — the agent's own state (cpu/mem/last_seen) was already saved
# synchronously above, and the next successful tick picks the aggregate metrics back up.
_MAX_INFLIGHT_TELEMETRY_TASKS = int(os.environ.get("NETINSIGHT_MAX_INFLIGHT_TELEMETRY_TASKS", "16"))
_telemetry_inflight_semaphore = threading.BoundedSemaphore(_MAX_INFLIGHT_TELEMETRY_TASKS)


def handle_telemetry_ingestion(agent: Agent, stats_data: dict, packets_list: list[dict]) -> None:
    """Orchestrates system telemetry ingestion, metrics aggregation, and HMM predictions."""
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

        # 2. Spin off heavy queries and analysis to a background thread to prevent client timeouts.
        # Bounded by _telemetry_inflight_semaphore — see its definition above for rationale.
        if _telemetry_inflight_semaphore.acquire(blocking=False):
            _telemetry_pool.submit(_async_telemetry_worker, agent.id, stats_data, packets_list)
        else:
            logger.warning(
                f"Telemetry processing backlog full ({_MAX_INFLIGHT_TELEMETRY_TASKS} tasks in "
                f"flight); skipping heavy analytics for this tick from agent {agent.id}. "
                "Agent status (cpu/mem/last_seen) was still saved synchronously."
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

    # Throughput in bps
    throughput = (total_bytes * 8.0) / 10.0
    # Packet rate in pps
    packet_rate = float(packet_count) / 10.0

    # Bandwidth utilization relative to link capacity
    from netinsight.config import settings
    link_capacity = getattr(settings, "LINK_CAPACITY", 100_000_000.0)
    bandwidth_util = (throughput / link_capacity) * 100.0

    # Latency: derived from the reporting agent's measured HTTP round-trip time to this server
    # (agent/sender.py times its own request and reports it as rtt_seconds on the *next* cycle).
    # Falls back to a conservative fixed estimate only when an agent doesn't report RTT
    # (older agent builds, or synthetic DEMO_MODE data).
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

    # Packet loss: primarily derived from true TCP retransmissions — the same 5-tuple + TCP
    # sequence number captured more than once in this window, which is the actual protocol-level
    # definition of a retransmission (RFC 793 §3.7). Both agents now capture tcp_seq
    # (agent/sniffer.py, agent_go/sniffer/sniffer.go). Deliberately independent of the threat
    # classifier's own output — a previous version derived "loss" from FlowRecord.threat_label
    # counts, which meant an attack label inflated packet_loss, which pushed the HMM toward
    # "Under Attack", which the DSE then reported as if it were independent corroboration of the
    # same attack.
    total_tcp = active_packets.filter(protocol="TCP").count()
    if total_tcp > 0:
        tcp_with_seq = active_packets.filter(protocol="TCP", tcp_seq__isnull=False)
        seq_coverage = tcp_with_seq.count()

        if seq_coverage > 0:
            retransmission_groups = (
                tcp_with_seq
                .values("src_ip", "dst_ip", "src_port", "dst_port", "tcp_seq")
                .annotate(occurrences=Count("id"))
                .filter(occurrences__gt=1)
            )
            retransmission_like_packets = sum(max(0, g["occurrences"] - 1) for g in retransmission_groups)
            packet_loss = (float(retransmission_like_packets) / max(1, seq_coverage)) * 100.0
        else:
            # Fallback proxy for traffic without a captured sequence number (agent builds
            # predating this field, or synthetic DEMO_MODE data): near-duplicate packets
            # (identical 5-tuple + size). Still independent of the classifier's own output —
            # just a coarser signal than exact sequence-number matching.
            duplicate_groups = (
                active_packets.filter(protocol="TCP")
                .values("src_ip", "dst_ip", "src_port", "dst_port", "size")
                .annotate(occurrences=Count("id"))
                .filter(occurrences__gt=1)
            )
            retransmission_like_packets = sum(max(0, g["occurrences"] - 1) for g in duplicate_groups)
            packet_loss = (float(retransmission_like_packets) / max(1, total_tcp)) * 100.0
    else:
        packet_loss = 0.0

    # Commit calculated metrics to MetricRecord
    MetricRecord.objects.create(
        timestamp=now_ts,
        throughput=throughput,
        packet_rate=packet_rate,
        bandwidth_util=bandwidth_util,
        latency=latency,
        packet_loss=packet_loss
    )

    # C. Gather HMM Observation Vector — Majority Vote from last 30s of threat records
    # Prevents a single false positive from permanently poisoning HMM state
    threat_label = "Normal"
    recent_threats = ThreatHistory.objects.filter(
        timestamp__gte=timezone.now() - timedelta(seconds=30)
    ).values_list("threat_type", flat=True)

    if recent_threats.exists():
        threat_counts = {}
        total = 0
        for t in recent_threats:
            threat_counts[t] = threat_counts.get(t, 0) + 1
            total += 1

        normal_count = threat_counts.get("Normal", 0)
        # If 80%+ of recent records are Normal, report Normal to HMM
        if total > 0 and (normal_count / total) >= 0.8:
            threat_label = "Normal"
        else:
            # Use the most frequent non-Normal threat
            non_normal = {k: v for k, v in threat_counts.items() if k != "Normal"}
            threat_label = (
                max(non_normal, key=non_normal.get)
                if non_normal
                else "Normal"
            )

    online_cutoff = timezone.now() - timedelta(seconds=15)
    online_agents = Agent.objects.filter(last_seen__gte=online_cutoff)
    total_sockets = online_agents.aggregate(total_sockets=Sum("active_connections"))["total_sockets"] or 0

    # D. Decode Hidden State Sequence
    recent_metrics = MetricRecord.objects.all().order_by("-timestamp")[:5]
    observations_history = []

    for metric in reversed(recent_metrics):
        observations_history.append({
            "util": metric.bandwidth_util,
            "latency": metric.latency,
            "loss": metric.packet_loss,
            "threat_label": threat_label,
            "packet_rate": metric.packet_rate,
            "sockets": float(total_sockets)
        })

    if not observations_history:
        observations_history.append({
            "util": bandwidth_util,
            "latency": latency,
            "loss": packet_loss,
            "threat_label": threat_label,
            "packet_rate": packet_rate,
            "sockets": float(total_sockets)
        })

    decoded_states = hmm_model.decode_states(observations_history)
    current_state = decoded_states[-1] if decoded_states else "Normal"

    # Save to StateHistory database
    StateHistory.objects.create(
        timestamp=now_ts,
        network_state=current_state,
        bandwidth_utilization=bandwidth_util / 100.0,
        packet_loss=packet_loss / 100.0,
        latency=latency
    )

    # Pruning of stale records is handled by the periodic background task
    # (see _prune_stale_records() / start_periodic_pruner() below), not per-request. Running 5
    # DELETE statements on every single agent's every telemetry tick was a measurable source of
    # SQLite write-lock contention under concurrent agents (evidenced by the "locked"-retry loops
    # throughout this module).


_PRUNE_INTERVAL_SECONDS = float(os.environ.get("NETINSIGHT_PRUNE_INTERVAL_SECONDS", "60"))


def _prune_stale_records() -> None:
    """Deletes stale records across all tables. Runs on a periodic timer instead of on every
    telemetry request (see start_periodic_pruner())."""
    close_old_connections()
    try:
        now_ts = time.time()
        prune_cutoff = now_ts - 600.0
        PacketRecord.objects.filter(timestamp__lt=prune_cutoff).delete()

        retention_cutoff = now_ts - 86400.0  # 24 hours
        FlowRecord.objects.filter(end_time__lt=retention_cutoff).delete()
        MetricRecord.objects.filter(timestamp__lt=retention_cutoff).delete()
        StateHistory.objects.filter(timestamp__lt=retention_cutoff).delete()
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
    """Starts the background pruning thread, guarded by a cross-process singleton lock so a
    multi-worker gunicorn deployment doesn't run N redundant copies of it."""
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

