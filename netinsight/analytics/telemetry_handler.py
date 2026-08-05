import logging
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import timedelta

from django.db import close_old_connections
from django.db.models import Sum
from django.utils import timezone

from netinsight.analytics.flow_builder import process_incoming_packet
from netinsight.dashboard.models import Agent, FlowRecord, MetricRecord, PacketRecord, StateHistory, ThreatHistory
from netinsight.prediction.hmm import HiddenMarkovModel

logger = logging.getLogger(__name__)
hmm_model = HiddenMarkovModel()

# Bounded thread pool prevents unbounded thread creation under high agent load
_telemetry_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="telemetry")

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
        agent.save()

        # 2. Spin off heavy queries and analysis to a background thread to prevent client timeouts
        _telemetry_pool.submit(_async_telemetry_worker, agent.id, stats_data, packets_list)

    except Exception as e:
        logger.error(f"Error handling telemetry payload: {e}", exc_info=True)


def _async_telemetry_worker(agent_id: int, stats_data: dict, packets_list: list[dict]) -> None:
    """Handles heavy processing tasks asynchronously without blocking client uploads."""
    close_old_connections()
    try:
        agent = Agent.objects.get(id=agent_id)
        now_ts = time.time()

        # A. Process and Classify all incoming packets
        for pkt in packets_list:
            process_incoming_packet(agent, pkt)

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

        # Latency approximation
        latency = 0.015

        # Packet Loss approximation
        total_tcp = active_packets.filter(protocol="TCP").count()
        retrans_count = 0
        if total_tcp > 0:
            attack_packets = FlowRecord.objects.filter(
                end_time__gte=window_start,
                threat_label__in=["DoS", "DDoS", "Mirai"]
            ).aggregate(total=Sum("packet_count"))["total"] or 0

            high_count_flows = FlowRecord.objects.filter(
                end_time__gte=window_start,
                packet_count__gt=50
            ).exclude(threat_label__in=["DoS", "DDoS", "Mirai"]).count()

            retrans_count = int(attack_packets * 0.08) + high_count_flows
            packet_loss = (float(retrans_count) / max(1, total_tcp)) * 100.0
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

        # E. Database Pruner: Delete raw PacketRecord entries older than 10 minutes (600s)
        prune_cutoff = now_ts - 600.0
        PacketRecord.objects.filter(timestamp__lt=prune_cutoff).delete()

        # Prune stale records older than 24 hours to prevent unbounded DB growth
        retention_cutoff = now_ts - 86400.0  # 24 hours
        FlowRecord.objects.filter(end_time__lt=retention_cutoff).delete()
        MetricRecord.objects.filter(timestamp__lt=retention_cutoff).delete()
        StateHistory.objects.filter(timestamp__lt=retention_cutoff).delete()
        retention_cutoff_dt = timezone.now() - timedelta(hours=24)
        ThreatHistory.objects.filter(timestamp__lt=retention_cutoff_dt).delete()

    except Exception as e:
        logger.error(f"Error in async telemetry worker thread: {e}", exc_info=True)
    finally:
        close_old_connections()
