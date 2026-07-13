import sqlite3
import logging
from pathlib import Path
from netinsight.config.settings import DB_PATH

logger = logging.getLogger(__name__)

def get_connection() -> sqlite3.Connection:
    """Returns a standard sqlite3 Connection to the database path.
    
    Creates parent directories if necessary.
    """
    db_file = Path(DB_PATH)
    db_file.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    """Initializes the SQLite database schemas and indices.
    
    Creates the tables: packets, metrics, active_devices, and state_history.
    """
    logger.info("Initializing SQLite Database Schema...")
    conn = get_connection()
    cursor = conn.cursor()
    
    try:
        # Packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                size INTEGER,
                timestamp REAL,
                ttl INTEGER
            )
        """)
        
        # Metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                timestamp REAL PRIMARY KEY,
                throughput REAL,
                packet_rate REAL,
                bandwidth_util REAL,
                latency REAL,
                packet_loss REAL
            )
        """)
        
        # Active devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS active_devices (
                ip TEXT PRIMARY KEY,
                last_seen REAL,
                total_bytes INTEGER
            )
        """)
        
        # State history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS state_history (
                timestamp REAL PRIMARY KEY,
                network_state TEXT,
                bandwidth_utilization REAL,
                packet_loss REAL,
                latency REAL
            )
        """)
        
        # Create indexes for optimized queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_state_history_timestamp ON state_history(timestamp)")
        
        conn.commit()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}", exc_info=True)
        conn.rollback()
        raise e
    finally:
        conn.close()

def save_packets_bulk(packets_list: list[dict]) -> None:
    """Saves a batch of packets to the packets table in a single transaction.
    
    Each dict should contain: src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp, ttl
    """
    if not packets_list:
        return
        
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.executemany("""
            INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, size, timestamp, ttl)
            VALUES (:src_ip, :dst_ip, :src_port, :dst_port, :protocol, :size, :timestamp, :ttl)
        """, packets_list)
        conn.commit()
    except Exception as e:
        logger.error(f"Error saving packets bulk: {e}", exc_info=True)
        conn.rollback()
    finally:
        conn.close()

def save_metric(timestamp: float, throughput: float, packet_rate: float, bandwidth_util: float, latency: float, packet_loss: float) -> None:
    """Saves a network metrics entry."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO metrics (timestamp, throughput, packet_rate, bandwidth_util, latency, packet_loss)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (timestamp, throughput, packet_rate, bandwidth_util, latency, packet_loss))
        conn.commit()
    except Exception as e:
        logger.error(f"Error saving network metric: {e}", exc_info=True)
        conn.rollback()
    finally:
        conn.close()

def update_active_device(ip: str, last_seen: float, bytes_added: int) -> None:
    """Updates last_seen and increments total_bytes for a given IP."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO active_devices (ip, last_seen, total_bytes)
            VALUES (?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                last_seen = excluded.last_seen,
                total_bytes = total_bytes + excluded.total_bytes
        """, (ip, last_seen, bytes_added))
        conn.commit()
    except Exception as e:
        logger.error(f"Error updating active device: {e}", exc_info=True)
        conn.rollback()
    finally:
        conn.close()

def save_state_history(timestamp: float, network_state: str, bandwidth_utilization: float, packet_loss: float, latency: float) -> None:
    """Saves a state history record for prediction and Markov processes."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO state_history (timestamp, network_state, bandwidth_utilization, packet_loss, latency)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, network_state, bandwidth_utilization, packet_loss, latency))
        conn.commit()
    except Exception as e:
        logger.error(f"Error saving state history: {e}", exc_info=True)
        conn.rollback()
    finally:
        conn.close()

def clear_db() -> None:
    """Clears all tables for fresh runs."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM packets")
        cursor.execute("DELETE FROM metrics")
        cursor.execute("DELETE FROM active_devices")
        cursor.execute("DELETE FROM state_history")
        conn.commit()
    except Exception as e:
        logger.error(f"Error clearing tables: {e}", exc_info=True)
        conn.rollback()
    finally:
        conn.close()
