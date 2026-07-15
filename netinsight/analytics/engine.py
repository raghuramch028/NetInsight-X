import logging
import math
import time

import pandas as pd

from netinsight.database import db_manager

logger = logging.getLogger(__name__)

class AnalyticsEngine:
    """Computes traffic statistics, protocol distributions, and devices activity.

    All calculations are done using Pandas and SQLite.
    Each method includes mathematical and assumption notes.
    """

    def __init__(self):
        pass

    def get_latest_metrics(self) -> dict:
        """Retrieves the most recent entry from the metrics table.

        If no data is present, returns default zero metrics to handle empty states gracefully.
        """
        conn = db_manager.get_connection()
        try:
            df = pd.read_sql_query(
                "SELECT * FROM metrics ORDER BY timestamp DESC LIMIT 1",
                conn
            )
            if df.empty:
                return {
                    "timestamp": time.time(),
                    "throughput": 0.0,
                    "packet_rate": 0.0,
                    "bandwidth_util": 0.0,
                    "latency": 0.015,
                    "packet_loss": 0.0
                }
            return df.iloc[0].to_dict()
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
        finally:
            conn.close()

    def get_historical_metrics(self, limit: int = 100) -> pd.DataFrame:
        """Retrieves a historical dataframe of computed metrics.

        Useful for analytical reports and plotting.
        """
        conn = db_manager.get_connection()
        try:
            df = pd.read_sql_query(
                "SELECT * FROM metrics ORDER BY timestamp DESC LIMIT ?",
                conn,
                params=(limit,)
            )
            if df.empty:
                return pd.DataFrame(columns=["timestamp", "throughput", "packet_rate", "bandwidth_util", "latency", "packet_loss"])
            return df.iloc[::-1].reset_index(drop=True)  # Order chronologically
        except Exception as e:
            logger.error(f"Error fetching historical metrics: {e}", exc_info=True)
            return pd.DataFrame(columns=["timestamp", "throughput", "packet_rate", "bandwidth_util", "latency", "packet_loss"])
        finally:
            conn.close()

    def get_protocol_distribution(self, window_seconds: float = 60.0) -> pd.DataFrame:
        """Computes the distribution of protocols within the given recent time window.

        Formula:
            Protocol % = (Count of Protocol Packets / Total Packets) * 100
        Assumptions:
            The IP header protocol field is intact and parsed correctly.
        Limitations:
            Encapsulated packets (VPNs, tunnels) will only show the outer protocol.
        """
        conn = db_manager.get_connection()
        try:
            cutoff = time.time() - window_seconds
            df = pd.read_sql_query(
                "SELECT protocol, COUNT(*) as packet_count, SUM(size) as byte_count "
                "FROM packets WHERE timestamp >= ? GROUP BY protocol",
                conn,
                params=(cutoff,)
            )
            if df.empty:
                return pd.DataFrame(columns=["protocol", "packet_count", "byte_count", "percentage"])

            total_pkts = df["packet_count"].sum()
            df["percentage"] = (df["packet_count"] / total_pkts) * 100.0 if total_pkts > 0 else 0.0
            return df
        except Exception as e:
            logger.error(f"Error computing protocol distribution: {e}", exc_info=True)
            return pd.DataFrame(columns=["protocol", "packet_count", "byte_count", "percentage"])
        finally:
            conn.close()

    def get_top_consumers(self, limit: int = 5, window_seconds: float = 60.0) -> pd.DataFrame:
        """Identifies top source IP addresses by cumulative traffic size.

        Formula:
            Traffic(IP) = Sum(Packet Size) for SrcIP = IP
        Assumptions:
            IP addresses are not spoofed and correspond to unique endpoints.
        Limitations:
            Grouping by IP does not separate multiple physical devices sharing a NAT IP.
        """
        conn = db_manager.get_connection()
        try:
            cutoff = time.time() - window_seconds
            df = pd.read_sql_query(
                "SELECT src_ip, COUNT(*) as packet_count, SUM(size) as total_bytes "
                "FROM packets WHERE timestamp >= ? GROUP BY src_ip "
                "ORDER BY total_bytes DESC LIMIT ?",
                conn,
                params=(cutoff, limit)
            )
            if df.empty:
                return pd.DataFrame(columns=["src_ip", "packet_count", "total_bytes", "percentage"])

            total_bytes_window = df["total_bytes"].sum()
            df["percentage"] = (df["total_bytes"] / total_bytes_window) * 100.0 if total_bytes_window > 0 else 0.0
            return df
        except Exception as e:
            logger.error(f"Error computing top consumers: {e}", exc_info=True)
            return pd.DataFrame(columns=["src_ip", "packet_count", "total_bytes", "percentage"])
        finally:
            conn.close()

    def get_active_devices_count(self, window_seconds: float = 300.0) -> int:
        """Returns the number of unique active source devices in the recent window.

        Assumptions:
            Devices emit at least one packet within the window to be counted.
        """
        conn = db_manager.get_connection()
        try:
            cutoff = time.time() - window_seconds
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM packets WHERE timestamp >= ?", (cutoff,))
            count = cursor.fetchone()[0]
            return count if count else 0
        except Exception as e:
            logger.error(f"Error getting active devices count: {e}", exc_info=True)
            return 0
        finally:
            conn.close()

    def get_general_summary(self, window_seconds: float = 60.0) -> dict:
        """Computes summary stats of traffic over the window."""
        conn = db_manager.get_connection()
        try:
            cutoff = time.time() - window_seconds
            df = pd.read_sql_query(
                "SELECT COUNT(*) as total_packets, SUM(size) as total_bytes, AVG(size) as avg_packet_size "
                "FROM packets WHERE timestamp >= ?",
                conn,
                params=(cutoff,)
            )

            if df.empty or df.iloc[0]["total_packets"] is None or df.iloc[0]["total_packets"] == 0:
                return {
                    "total_packets": 0,
                    "total_bytes": 0,
                    "avg_packet_size": 0.0,
                    "active_devices": 0
                }

            summary = df.iloc[0].to_dict()
            summary["active_devices"] = self.get_active_devices_count(window_seconds)
            return summary
        except Exception as e:
            logger.error(f"Error computing general summary: {e}", exc_info=True)
            return {
                "total_packets": 0,
                "total_bytes": 0,
                "avg_packet_size": 0.0,
                "active_devices": 0
            }
        finally:
            conn.close()

    def get_network_topology(self, window_seconds: float = 300.0, max_hosts: int = 8) -> dict:
        """Builds a dynamic network topology from active source hosts in the recent window.

        The central node is the DSS monitoring router, the top node is the WAN/Internet
        gateway, and host nodes are the most active source IPs by byte volume.
        """
        center_x, center_y = 160, 100
        radius = 80
        topology = {
            "router": {"label": "DSS Router Monitor", "x": center_x, "y": center_y},
            "wan": {"label": "Internet Gateway", "x": center_x, "y": 20},
            "hosts": [],
        }

        top_consumers = self.get_top_consumers(limit=max_hosts, window_seconds=window_seconds)
        if top_consumers.empty:
            return topology

        total_bytes = max(1, int(top_consumers["total_bytes"].sum()))
        hosts = []
        for _, row in top_consumers.iterrows():
            ip = str(row["src_ip"])
            short_label = ip.split(".")[-1] if "." in ip else ip[-4:]
            percentage = float(row["total_bytes"]) * 100.0 / total_bytes
            hosts.append({
                "ip": ip,
                "short_label": short_label,
                "total_bytes": int(row["total_bytes"]),
                "total_mb": float(row["total_bytes"]) / 1048576.0,
                "packet_count": int(row.get("packet_count", 0)),
                "percentage": percentage,
                "radius": max(10, min(16, int(10 + percentage / 25.0))),
            })

        n = len(hosts)
        for idx, host in enumerate(hosts):
            angle = math.pi / 2 if n == 1 else (idx * math.pi) / (n - 1)
            host["x"] = int(center_x + radius * math.cos(angle))
            host["y"] = int(center_y + radius * math.sin(angle))

        topology["hosts"] = hosts
        return topology
