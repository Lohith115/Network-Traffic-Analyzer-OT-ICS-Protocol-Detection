from capture import PacketCapture
from database import DatabaseManager
from scada_detector import SCADADetector
import threading
import time
import logging
from datetime import datetime
from collections import defaultdict
from typing import Dict, Any, List, Optional

# Module-level logger initialization
logger = logging.getLogger("network_traffic_analyzer.analyzer")

class TrafficAnalyzer:
    """
    Processes captured network packets, maintains statistics, and persists data.
    
    This class runs in a background thread, consuming packets from the PacketCapture
    queue, performing protocol analysis (including SCADA/OT detection), and
    updating the database with flow records, alerts, and protocol distributions.
    """

    def __init__(self, capture: PacketCapture, db: DatabaseManager, 
                 analysis_interval: float = 1.0):
        """
        Initializes the TrafficAnalyzer with required components.

        Args:
            capture (PacketCapture): The packet capture instance providing the packet queue.
            db (DatabaseManager): The database manager for persisting analysis results.
            analysis_interval (float): Seconds to wait between analysis processing cycles.
        """
        self.capture = capture
        self.db = db
        self.analysis_interval = analysis_interval
        self.stop_event = threading.Event()
        self.analysis_thread: Optional[threading.Thread] = None
        
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_counts": defaultdict(int),
            "top_talkers": defaultdict(int)
        }
        
        self.scada_detector = SCADADetector()
        self.logger = logging.getLogger("network_traffic_analyzer.analyzer")

    def start(self) -> None:
        """
        Starts the analysis loop in a background daemon thread.
        """
        self.stop_event.clear()
        self.analysis_thread = threading.Thread(target=self._analysis_loop, daemon=True)
        self.analysis_thread.start()
        self.logger.info("Traffic analyzer started")

    def stop(self) -> None:
        """
        Signals the analysis thread to stop and waits for it to terminate.
        """
        self.stop_event.set()
        if self.analysis_thread is not None:
            self.analysis_thread.join(timeout=5)
        self.logger.info("Traffic analyzer stopped")

    def _analysis_loop(self) -> None:
        """
        Main loop for the analysis thread.
        
        Periodically triggers packet processing and handles exceptions to ensure 
        the analyzer remains operational.
        """
        while not self.stop_event.is_set():
            try:
                self._process_packets()
            except Exception as e:
                self.logger.error(f"Error in analysis loop: {e}", exc_info=True)
            
            time.sleep(self.analysis_interval)

    def _process_packets(self) -> None:
        """
        Fetches a batch of packets and performs comprehensive analysis.
        
        Updates internal statistics, identifies potential SCADA threats, 
        and persists flow and protocol data to the database.
        """
        packets = self.capture.get_packets(max_packets=200)
        if not packets:
            return

        # Track protocol distribution for the current batch to batch-update DB
        batch_protocol_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

        for packet in packets:
            # Update internal cumulative statistics
            pkt_bytes = packet["bytes"]
            protocol = packet["protocol"]
            src_ip = packet["src_ip"]

            self.stats["total_packets"] += 1
            self.stats["total_bytes"] += pkt_bytes
            self.stats["protocol_counts"][protocol] += 1
            self.stats["top_talkers"][src_ip] += pkt_bytes

            # Update batch stats for database insertion
            batch_protocol_stats[protocol]["packets"] += 1
            batch_protocol_stats[protocol]["bytes"] += pkt_bytes

            # Persist individual flow to database
            try:
                self.db.insert_flow(
                    timestamp=datetime.fromisoformat(packet["timestamp"]),
                    src_ip=src_ip,
                    dst_ip=packet["dst_ip"],
                    src_port=packet["src_port"],
                    dst_port=packet["dst_port"],
                    protocol=protocol,
                    bytes=pkt_bytes,
                    duration=0
                )
            except Exception as e:
                self.logger.error(f"Failed to insert flow: {e}")

            # Perform SCADA/OT security analysis
            try:
                alert = self.scada_detector.analyze(packet)
                if alert:
                    self.db.insert_alert(
                        timestamp=datetime.now(),
                        alert_type=alert["alert_type"],
                        severity=alert["severity"],
                        description=alert.get("description")
                    )
            except Exception as e:
                self.logger.error(f"Error during SCADA detection: {e}")

        # Update protocol statistics in DB after batch processing
        for proto, data in batch_protocol_stats.items():
            try:
                self.db.insert_protocol(
                    timestamp=datetime.now(),
                    protocol_name=proto,
                    packet_count=data["packets"],
                    byte_count=data["bytes"]
                )
            except Exception as e:
                self.logger.error(f"Failed to update protocol stats for {proto}: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns a snapshot of current traffic statistics.

        Returns:
            Dict[str, Any]: A dictionary containing total counts, protocol 
            distribution, and the top 10 talkers by byte volume.
        """
        # Sort top talkers and take top 10
        sorted_talkers = sorted(
            self.stats["top_talkers"].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:10]

        return {
            "total_packets": self.stats["total_packets"],
            "total_bytes": self.stats["total_bytes"],
            "protocol_distribution": dict(self.stats["protocol_counts"]),
            "top_talkers": dict(sorted_talkers)
        }

    def reset_stats(self) -> None:
        """
        Resets all internal cumulative statistics to their initial state.
        """
        self.stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "protocol_counts": defaultdict(int),
            "top_talkers": defaultdict(int)
        }
        self.logger.info("Stats reset")
