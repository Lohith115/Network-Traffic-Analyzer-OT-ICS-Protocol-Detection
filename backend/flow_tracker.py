from database import DatabaseManager
import threading
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

# Module-level logger initialization
logger = logging.getLogger("network_traffic_analyzer.flow_tracker")

class FlowTracker:
    """
    Tracks and manages network sessions (flows) based on the 5-tuple.

    A flow is uniquely identified by (source IP, source port, destination IP, 
    destination port, protocol). This class maintains state for active flows, 
    handles updates from incoming packets, and flushes completed or expired 
    flows to the database.
    """

    def __init__(self, db: DatabaseManager, flow_timeout: int = 60):
        """
        Initializes the FlowTracker.

        Args:
            db (DatabaseManager): The database manager instance for persisting flows.
            flow_timeout (int): Seconds of inactivity before an active flow is considered expired.
        """
        self.db = db
        self.flow_timeout = flow_timeout
        self.active_flows: Dict[Tuple, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self.logger = logging.getLogger("network_traffic_analyzer.flow_tracker")

    def _make_flow_key(self, packet: Dict[str, Any]) -> Tuple:
        """
        Generates a 5-tuple flow key from a packet dictionary.

        Args:
            packet (Dict[str, Any]): The processed packet metadata.

        Returns:
            Tuple: (src_ip, src_port, dst_ip, dst_port, protocol)
        """
        return (
            packet["src_ip"],
            packet.get("src_port"),
            packet["dst_ip"],
            packet.get("dst_port"),
            packet["protocol"]
        )

    def update(self, packet: Dict[str, Any]) -> None:
        """
        Updates an existing flow or creates a new one based on the incoming packet.

        Checks for TCP flags (FIN/RST) to determine if a flow should be closed 
        immediately. This method is thread-safe.

        Args:
            packet (Dict[str, Any]): The packet metadata to process.
        """
        try:
            key = self._make_flow_key(packet)
            now = datetime.now()

            with self._lock:
                if key in self.active_flows:
                    flow = self.active_flows[key]
                    flow["last_seen"] = now
                    flow["packet_count"] += 1
                    flow["byte_count"] += packet.get("bytes", 0)
                else:
                    self.active_flows[key] = {
                        "src_ip": packet["src_ip"],
                        "dst_ip": packet["dst_ip"],
                        "src_port": packet.get("src_port"),
                        "dst_port": packet.get("dst_port"),
                        "protocol": packet["protocol"],
                        "start_time": now,
                        "last_seen": now,
                        "packet_count": 1,
                        "byte_count": packet.get("bytes", 0),
                        "state": "ACTIVE"
                    }

                # Check for TCP termination flags
                if packet.get("protocol") == "TCP" and "tcp_flags" in packet:
                    flags = packet["tcp_flags"]
                    # F: FIN, R: RST
                    if "F" in flags or "R" in flags:
                        self.active_flows[key]["state"] = "CLOSED"
                        self._flush_flow(key)

        except Exception as e:
            self.logger.error(f"Error updating flow: {e}", exc_info=True)

    def _flush_flow(self, key: Tuple) -> None:
        """
        Calculates flow metrics, persists to database, and removes from active flows.

        Note: This method assumes the caller holds the self._lock if it's not 
        called from within a locked block. In the current implementation, 
        it is called while the lock is held in update() and cleanup_expired_flows().

        Args:
            key (Tuple): The 5-tuple key of the flow to flush.
        """
        flow = self.active_flows.get(key)
        if not flow:
            return

        duration = (flow["last_seen"] - flow["start_time"]).total_seconds()
        
        try:
            self.db.insert_flow(
                timestamp=flow["start_time"].isoformat(),
                src_ip=flow["src_ip"],
                dst_ip=flow["dst_ip"],
                src_port=flow["src_port"],
                dst_port=flow["dst_port"],
                protocol=flow["protocol"],
                bytes=flow["byte_count"],
                duration=duration
            )
            
            self.logger.debug(
                f"Flow flushed: {key}, duration={duration:.2f}s, "
                f"packets={flow['packet_count']}"
            )
        except Exception as e:
            self.logger.error(f"Failed to persist flushed flow: {e}")
        finally:
            del self.active_flows[key]

    def cleanup_expired_flows(self) -> int:
        """
        Identifies and flushes flows that have exceeded the inactivity timeout.

        Returns:
            int: The number of flows that were cleaned up.
        """
        now = datetime.now()
        expired_keys = []

        with self._lock:
            for key, flow in self.active_flows.items():
                if (now - flow["last_seen"]).total_seconds() > self.flow_timeout:
                    expired_keys.append(key)

            for key in expired_keys:
                self._flush_flow(key)

        count = len(expired_keys)
        if count > 0:
            self.logger.info(f"Cleaned up {count} expired flows")
        
        return count

    def get_active_flow_count(self) -> int:
        """
        Returns the current number of active flows being tracked.

        Returns:
            int: The count of active flows.
        """
        with self._lock:
            return len(self.active_flows)

    def get_active_flows(self) -> List[Dict[str, Any]]:
        """
        Returns a snapshot list of all currently active flows.

        Returns:
            List[Dict[str, Any]]: A list of flow dictionaries.
        """
        with self._lock:
            # Return a copy of the flow dicts to prevent external mutation
            return [flow.copy() for flow in self.active_flows.values()]
