import logging
import time
from datetime import timedelta

import pandas as pd
from django.utils import timezone

from netinsight.dashboard.models import Agent, MetricRecord

logger = logging.getLogger(__name__)

class AnalyticsEngine:
    """Computes traffic statistics, protocol distributions, and devices activity using Django ORM."""

    def __init__(self):
        pass

    def get_latest_metrics(self) -> dict:
        """Retrieves the most recent entry from the MetricRecord table."""
        try:
            record = MetricRecord.objects.all().order_by("-timestamp").first()
            if not record:
                return {
                    "timestamp": time.time(),
                    "throughput": 0.0,
                    "packet_rate": 0.0,
                    "bandwidth_util": 0.0,
                    "latency": 0.015,
                    "packet_loss": 0.0
                }
            return {
                "timestamp": record.timestamp,
                "throughput": record.throughput,
                "packet_rate": record.packet_rate,
                "bandwidth_util": record.bandwidth_util,
                "latency": record.latency,
                "packet_loss": record.packet_loss
            }
        except Exception as e:
            logger.error(f"Error fetching latest metrics: {e}", exc_info=True)
            return {
                "timestamp": time.time(),
                "throughput": 0.0,
                "packet_rate": 0.0,
                "bandwidth_util": 0.0,
                "latency": 0.015,
                "packet_loss": 0.0
            }

    def get_historical_metrics(self, limit: int = 100) -> pd.DataFrame:
        """Retrieves a historical dataframe of computed metrics."""
        try:
            records = MetricRecord.objects.all().order_by("-timestamp")[:limit]
            data = [
                {
                    "timestamp": r.timestamp,
                    "throughput": r.throughput,
                    "packet_rate": r.packet_rate,
                    "bandwidth_util": r.bandwidth_util,
                    "latency": r.latency,
                    "packet_loss": r.packet_loss
                }
                for r in reversed(records)
            ]
            if not data:
                return pd.DataFrame(columns=["timestamp", "throughput", "packet_rate", "bandwidth_util", "latency", "packet_loss"])
            return pd.DataFrame(data)
        except Exception as e:
            logger.error(f"Error fetching historical metrics: {e}", exc_info=True)
            return pd.DataFrame(columns=["timestamp", "throughput", "packet_rate", "bandwidth_util", "latency", "packet_loss"])

    def get_active_devices_count(self, window_seconds: float = 15.0) -> int:
        """Returns the number of unique active source devices in the recent window or total registered agents."""
        try:
            cutoff = timezone.now() - timedelta(seconds=window_seconds)
            cnt = Agent.objects.filter(last_seen__gte=cutoff).count()
            return cnt if cnt > 0 else Agent.objects.count()
        except Exception as e:
            logger.error(f"Error getting active devices count: {e}", exc_info=True)
            return 0

