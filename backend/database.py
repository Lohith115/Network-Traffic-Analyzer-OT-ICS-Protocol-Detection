# database.py
"""
Production-ready SQLite database module for Network Traffic Analyzer.
Handles schema creation, flow/protocol/alert storage, and indexing.
Includes comprehensive logging, type hints, and thread-safe operations.

FIXED VERSION - Corrected SQL queries and added port columns
"""

import sqlite3
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import closing

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("network_traffic_analyzer.db")

# Database path (can be changed to a config file or env var)
DB_PATH = "./network_traffic_analyzer.db"


class DatabaseManager:
    """
    Thread-safe SQLite manager for storing network flows, protocols, and alerts.
    Uses connection pooling via context managers for safe multi-thread access.
    """

    def __init__(self, db_path: str = DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """
        Creates tables if they don't exist.
        Runs once at startup.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    self._create_tables(conn)
            logger.info("Database initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise

    def _create_tables(self, conn) -> None:
        """
        Creates tables for flows, protocols, and alerts with indexes.
        """
        try:
            # Flows table (FIXED: Added ports)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    bytes INTEGER NOT NULL,
                    duration INTEGER NOT NULL
                );
            """)
            # Indexes for fast queries
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_protocol ON flows(protocol);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_src_ip ON flows(src_ip);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_flows_dst_ip ON flows(dst_ip);")

            # Protocols table (FIXED: Added UNIQUE constraint for UPSERT)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS protocols (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    protocol_name TEXT NOT NULL UNIQUE,
                    packet_count INTEGER NOT NULL DEFAULT 0,
                    byte_count INTEGER NOT NULL DEFAULT 0
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prot_timestamp ON protocols(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_prot_name ON protocols(protocol_name);")

            # Alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);")

            logger.info("All tables created or verified.")
        except Exception as e:
            logger.error(f"Failed to create tables: {e}")
            raise

    def insert_flow(self, timestamp: datetime, src_ip: Optional[str], dst_ip: Optional[str],
                   protocol: str, bytes: int, duration: int, 
                   src_port: Optional[int] = None, dst_port: Optional[int] = None) -> bool:
        """
        Inserts a flow record into the `flows` table.
        Returns True on success, False on error.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.execute("""
                        INSERT INTO flows (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes, duration)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (timestamp.isoformat(), src_ip, dst_ip, src_port, dst_port, protocol, bytes, duration))
            logger.debug(f"Inserted flow: {timestamp} {src_ip}:{src_port} -> {dst_ip}:{dst_port} {protocol}")
            return True
        except Exception as e:
            logger.error(f"Failed to insert flow: {e}")
            return False

    def insert_protocol(self, timestamp: datetime, protocol_name: str,
                       packet_count: int = 0, byte_count: int = 0) -> bool:
        """
        Inserts or updates protocol statistics using UPSERT.
        FIXED: Now uses single-query UPSERT instead of SELECT + UPDATE/INSERT.
        Returns True on success, False on error.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.execute("""
                        INSERT INTO protocols (timestamp, protocol_name, packet_count, byte_count)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(protocol_name) DO UPDATE SET
                            packet_count = packet_count + excluded.packet_count,
                            byte_count = byte_count + excluded.byte_count,
                            timestamp = excluded.timestamp
                    """, (timestamp.isoformat(), protocol_name, packet_count, byte_count))
            logger.debug(f"Protocol stats updated: {protocol_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to insert/update protocol: {e}")
            return False

    def insert_alert(self, timestamp: datetime, alert_type: str,
                    severity: str, description: Optional[str] = None) -> bool:
        """
        Inserts an alert record into the `alerts` table.
        Returns True on success, False on error.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                with conn:
                    conn.execute("""
                        INSERT INTO alerts (timestamp, alert_type, severity, description)
                        VALUES (?, ?, ?, ?)
                    """, (timestamp.isoformat(), alert_type, severity, description))
            logger.warning(f"Alert inserted: {alert_type} ({severity})")
            return True
        except Exception as e:
            logger.error(f"Failed to insert alert: {e}")
            return False

    def get_flow_stats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Returns recent flow records (limit by default 100).
        Returns list of dicts.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute(
                    "SELECT * FROM flows ORDER BY timestamp DESC LIMIT ?", (limit,)
                )
                rows = cursor.fetchall()
                return [
                    {
                        "id": row[0],
                        "timestamp": row[1],
                        "src_ip": row[2],
                        "dst_ip": row[3],
                        "src_port": row[4],
                        "dst_port": row[5],
                        "protocol": row[6],
                        "bytes": row[7],
                        "duration": row[8],
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to fetch flow stats: {e}")
            return []

    def get_protocol_stats(self) -> List[Dict[str, Any]]:
        """
        Returns protocol distribution stats (packet count, byte count).
        FIXED: Now aggregates properly with SUM() instead of just selecting rows.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute("""
                    SELECT protocol_name, 
                           SUM(packet_count) AS total_packets, 
                           SUM(byte_count) AS total_bytes
                    FROM protocols
                    WHERE packet_count > 0
                    GROUP BY protocol_name
                    ORDER BY total_packets DESC
                """)
                rows = cursor.fetchall()
                return [
                    {
                        "protocol": row[0],
                        "packet_count": row[1],
                        "bytes": row[2],
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to fetch protocol stats: {e}")
            return []

    def get_top_talkers(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Returns top talkers (by total bandwidth) across all connections.
        FIXED: Now aggregates per IP (not per connection pair).
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute("""
                    WITH ip_totals AS (
                        SELECT src_ip AS ip, SUM(bytes) AS bytes FROM flows WHERE src_ip IS NOT NULL GROUP BY src_ip
                        UNION ALL
                        SELECT dst_ip AS ip, SUM(bytes) AS bytes FROM flows WHERE dst_ip IS NOT NULL GROUP BY dst_ip
                    )
                    SELECT ip, SUM(bytes) AS total_bytes
                    FROM ip_totals
                    GROUP BY ip
                    ORDER BY total_bytes DESC
                    LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                return [
                    {
                        "ip": row[0],
                        "bytes": row[1],
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to fetch top talkers: {e}")
            return []

    def get_alerts(self, severity: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Returns alerts (limited by severity filter if provided).
        """
        try:
            query = "SELECT * FROM alerts"
            params = []
            if severity:
                query += " WHERE severity = ?"
                params.append(severity)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute(query, params)
                rows = cursor.fetchall()
                return [
                    {
                        "id": row[0],
                        "timestamp": row[1],
                        "alert_type": row[2],
                        "severity": row[3],
                        "description": row[4],
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to fetch alerts: {e}")
            return []

    def get_alerts_recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Returns most recent alerts.
        """
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute(
                    "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
                )
                rows = cursor.fetchall()
                return [
                    {
                        "id": row[0],
                        "timestamp": row[1],
                        "alert_type": row[2],
                        "severity": row[3],
                        "description": row[4],
                    }
                    for row in rows
                ]
        except Exception as e:
            logger.error(f"Failed to fetch recent alerts: {e}")
            return []

    def get_total_flows_count(self) -> int:
        """Returns total number of flow records in the database."""
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM flows")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to count flows: {e}")
            return 0

    def get_total_alerts_count(self) -> int:
        """Returns total number of alert records in the database."""
        try:
            with closing(sqlite3.connect(self.db_path)) as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM alerts")
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Failed to count alerts: {e}")
            return 0

    def get_db_connection(self) -> sqlite3.Connection:
        """
        Returns a connection object (for advanced use).
        """
        return sqlite3.connect(self.db_path)


# Global instance (optional - can be created in main app)
db_manager = DatabaseManager()


# Example usage (for testing or standalone runs):
if __name__ == "__main__":
    # Example: Insert a test flow
    db_manager.insert_flow(
        timestamp=datetime.now(),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        bytes=1024,
        duration=300
    )
    # Example: Get top talkers
    print("Top Talkers:", db_manager.get_top_talkers(5))
    print("Protocol Stats:", db_manager.get_protocol_stats())