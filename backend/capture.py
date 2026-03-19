from scapy.all import sniff, get_if_list, IP, TCP, UDP, ICMP
import threading
import queue
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

class PacketCapture:
    """
    Handles live network packet capture using Scapy in a background thread.
    
    This class provides a non-blocking interface to capture packets from a 
    specified network interface, process them into a dictionary format, 
    and store them in a thread-safe queue for further analysis.
    """

    def __init__(self, interface: str, bpf_filter: str = "", queue_size: int = 1000):
        """
        Initializes the PacketCapture instance with configuration parameters.

        Args:
            interface (str): The name of the network interface to sniff (e.g., 'eth0', 'wlan0').
            bpf_filter (str): Berkeley Packet Filter string to filter captured traffic.
            queue_size (int): Maximum number of packets the internal queue can hold.
        """
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.stop_event = threading.Event()
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.capture_thread: Optional[threading.Thread] = None
        self._packet_count = 0
        self._count_lock = threading.Lock()
        self.logger = logging.getLogger("network_traffic_analyzer.capture")

    def start(self) -> None:
        """
        Starts the packet capture process in a background daemon thread.

        Validates the network interface existence before initializing the thread.
        Handles Windows-specific GUID interface names by providing helpful error messages.

        Raises:
            ValueError: If the specified interface is not found in the system interface list.
        """
        if self.is_running():
            self.logger.warning("Capture already running, ignoring start() call")
            return

        interfaces = get_if_list()
        if self.interface not in interfaces:
            self.logger.error(
                f"Interface '{self.interface}' not found. "
                f"Available interfaces: {interfaces}"
            )
            raise ValueError(
                f"Interface '{self.interface}' not found. "
                f"On Windows use the NPF GUID from get_if_list(). "
                f"Available: {interfaces}"
            )

        self.stop_event.clear()
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        self.logger.info(f"Capture started on interface {self.interface}")

    def stop(self) -> None:
        """
        Signals the capture thread to stop and waits for it to terminate.
        
        The thread is joined with a 5-second timeout to ensure the main process 
        isn't blocked indefinitely.
        """
        self.stop_event.set()
        if self.capture_thread is not None:
            self.capture_thread.join(timeout=5)
        
        with self._count_lock:
            count = self._packet_count
        self.logger.info(f"Capture stopped. Total packets captured: {count}")

    def _capture_loop(self) -> None:
        """
        The main capture loop executed in a background thread.
        
        Calls Scapy's sniff function with a stop filter linked to the stop_event.
        Handles permission errors and general exceptions during the capture lifecycle.

        Raises:
            PermissionError: If the process does not have sufficient privileges for raw sockets.
        """
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                store=False,
                stop_filter=lambda x: self.stop_event.is_set(),
                filter=self.bpf_filter if self.bpf_filter else None
            )
        except PermissionError:
            self.logger.error("Root/admin privileges required for packet capture")
            raise
        except Exception as e:
            self.logger.error(f"Capture loop error: {e}")

    def _packet_handler(self, packet) -> None:
        """
        Processes a raw Scapy packet into a structured dictionary.

        Extracts IP addresses, ports, protocol names, byte lengths, and TCP flags.
        Only processes packets containing an IP layer.

        Args:
            packet: The raw packet object captured by Scapy.
        """
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_len = len(packet)

        # Protocol determination and port extraction
        protocol = ""
        src_port = None
        dst_port = None
        tcp_flags = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            protocol = str(packet[IP].proto)

        packet_dict = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "bytes": packet_len
        }
        
        if tcp_flags:
            packet_dict["tcp_flags"] = tcp_flags

        with self._count_lock:
            self._packet_count += 1

        try:
            self.packet_queue.put_nowait(packet_dict)
        except queue.Full:
            self.logger.warning("Packet queue full — dropping packet")

        with self._count_lock:
            current_count = self._packet_count
        if current_count % 100 == 0:
            self.logger.debug(f"Captured {current_count} packets")

    def get_packets(self, max_packets: int = 100) -> List[Dict[str, Any]]:
        """
        Drains and returns up to max_packets from the internal packet queue.

        Args:
            max_packets (int): The maximum number of packet dictionaries to retrieve.

        Returns:
            List[Dict[str, Any]]: A list of processed packet metadata dictionaries.
        """
        packets = []
        for _ in range(max_packets):
            try:
                packets.append(self.packet_queue.get_nowait())
            except queue.Empty:
                break
        return packets

    def get_queue_size(self) -> int:
        """
        Returns the current number of items in the packet queue.

        Returns:
            int: The current size of the queue.
        """
        return self.packet_queue.qsize()

    def is_running(self) -> bool:
        """
        Checks if the capture background thread is currently active.

        Returns:
            bool: True if the thread is alive and running, False otherwise.
        """
        return self.capture_thread is not None and self.capture_thread.is_alive()
