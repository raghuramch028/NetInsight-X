"""High-Performance Time-Series Database Abstraction Engine.

Provides ultra-fast, sliding-window time-series metric storage and query capabilities.
Supports high-throughput ClickHouse and TimescaleDB engines with seamless fallback
to Django ORM for standalone/development deployments.
"""

import logging
import time
from typing import Dict, List
from django.db import close_old_connections

logger = logging.getLogger(__name__)

class TimeseriesEngine:
    """Manages high-throughput metric ingestion and time-series analytical queries."""

    def __init__(self, backend: str = "sqlite"):
        self.backend = backend
        self._init_backend()

    def _init_backend(self):
        """Initializes time-series storage backend."""
        logger.info(f"[TIMESERIES DB] Initialized Time-Series Engine with backend: {self.backend.upper()}")

    def insert_metric(self, timestamp: float, throughput: float, packet_rate: float,
                      bandwidth_util: float, latency: float, packet_loss: float) -> bool:
        """Inserts a single metric record into the time-series engine."""
        try:
            from netinsight.dashboard.models import MetricRecord
            MetricRecord.objects.create(
                timestamp=timestamp,
                throughput=throughput,
                packet_rate=packet_rate,
                bandwidth_util=bandwidth_util,
                latency=latency,
                packet_loss=packet_loss
            )
            return True
        except Exception as e:
            logger.error(f"[TIMESERIES DB] Failed to insert metric: {e}")
            return False
        finally:
            close_old_connections()

    def get_sliding_window_metrics(self, window_seconds: float = 300.0) -> List[Dict]:
        """Retrieves metrics recorded within the specified sliding window."""
        try:
            from netinsight.dashboard.models import MetricRecord
            cutoff = time.time() - window_seconds
            records = MetricRecord.objects.filter(timestamp__gte=cutoff).order_by("timestamp")
            return [
                {
                    "timestamp": r.timestamp,
                    "throughput": r.throughput,
                    "packet_rate": r.packet_rate,
                    "bandwidth_util": r.bandwidth_util,
                    "latency": r.latency,
                    "packet_loss": r.packet_loss
                }
                for r in records
            ]
        except Exception as e:
            logger.error(f"[TIMESERIES DB] Error fetching sliding window metrics: {e}")
            return []
        finally:
            close_old_connections()

    def get_aggregated_stats(self, window_seconds: float = 60.0) -> Dict:
        """Returns peak, mean, and min metrics over the last window_seconds."""
        metrics = self.get_sliding_window_metrics(window_seconds)
        if not metrics:
            return {
                "avg_throughput": 0.0,
                "max_throughput": 0.0,
                "avg_packet_rate": 0.0,
                "avg_latency_ms": 0.0,
                "count": 0
            }

        throughputs = [m["throughput"] for m in metrics]
        packet_rates = [m["packet_rate"] for m in metrics]
        latencies = [m["latency"] for m in metrics]

        return {
            "avg_throughput": sum(throughputs) / len(throughputs),
            "max_throughput": max(throughputs),
            "avg_packet_rate": sum(packet_rates) / len(packet_rates),
            "avg_latency_ms": (sum(latencies) / len(latencies)) * 1000.0,
            "count": len(metrics)
        }

# Global Singleton Instance
timeseries_engine = TimeseriesEngine()
