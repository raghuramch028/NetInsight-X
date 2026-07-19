import logging
import time
from datetime import timedelta
import pandas as pd
from django.db.models import Count, Sum, Avg
from django.utils import timezone
from netinsight.dashboard.models import Agent, PacketRecord, MetricRecord

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

    def get_protocol_distribution(self, window_seconds: float = 60.0) -> pd.DataFrame:
        """Computes the distribution of protocols within the given recent time window."""
        try:
            cutoff = time.time() - window_seconds
            queryset = PacketRecord.objects.filter(timestamp__gte=cutoff).values("protocol").annotate(
                packet_count=Count("id"),
                byte_count=Sum("size")
            )
            df = pd.DataFrame(list(queryset))
            if df.empty:
                return pd.DataFrame(columns=["protocol", "packet_count", "byte_count", "percentage"])

            total_pkts = df["packet_count"].sum()
            df["percentage"] = (df["packet_count"] / total_pkts) * 100.0 if total_pkts > 0 else 0.0
            return df
        except Exception as e:
            logger.error(f"Error computing protocol distribution: {e}", exc_info=True)
            return pd.DataFrame(columns=["protocol", "packet_count", "byte_count", "percentage"])

    def get_top_consumers(self, limit: int = 5, window_seconds: float = 60.0) -> pd.DataFrame:
        """Identifies top source IP addresses by cumulative traffic size."""
        try:
            cutoff = time.time() - window_seconds
            queryset = PacketRecord.objects.filter(timestamp__gte=cutoff).values("src_ip").annotate(
                packet_count=Count("id"),
                total_bytes=Sum("size")
            ).order_by("-total_bytes")[:limit]
            df = pd.DataFrame(list(queryset))
            if df.empty:
                return pd.DataFrame(columns=["src_ip", "packet_count", "total_bytes", "percentage"])

            total_bytes_window = df["total_bytes"].sum()
            df["percentage"] = (df["total_bytes"] / total_bytes_window) * 100.0 if total_bytes_window > 0 else 0.0
            return df
        except Exception as e:
            logger.error(f"Error computing top consumers: {e}", exc_info=True)
            return pd.DataFrame(columns=["src_ip", "packet_count", "total_bytes", "percentage"])

    def get_active_devices_count(self, window_seconds: float = 15.0) -> int:
        """Returns the number of unique active source devices in the recent window."""
        try:
            cutoff = timezone.now() - timedelta(seconds=window_seconds)
            return Agent.objects.filter(last_seen__gte=cutoff).count()
        except Exception as e:
            logger.error(f"Error getting active devices count: {e}", exc_info=True)
            return 0

    def get_general_summary(self, window_seconds: float = 60.0) -> dict:
        """Computes summary stats of traffic over the window."""
        try:
            cutoff = time.time() - window_seconds
            stats = PacketRecord.objects.filter(timestamp__gte=cutoff).aggregate(
                total_packets=Count("id"),
                total_bytes=Sum("size"),
                avg_packet_size=Avg("size")
            )
            total_packets = stats.get("total_packets") or 0
            if total_packets == 0:
                return {
                    "total_packets": 0,
                    "total_bytes": 0,
                    "avg_packet_size": 0.0,
                    "active_devices": 0
                }

            return {
                "total_packets": total_packets,
                "total_bytes": stats.get("total_bytes") or 0,
                "avg_packet_size": stats.get("avg_packet_size") or 0.0,
                "active_devices": self.get_active_devices_count(window_seconds=15)
            }
        except Exception as e:
            logger.error(f"Error computing general summary: {e}", exc_info=True)
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "avg_packet_size": 0.0,
                "active_devices": 0
            }
