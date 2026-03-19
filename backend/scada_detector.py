import ipaddress
import logging
from typing import Dict, Any, Optional, List

# Module-level logger initialization
logger = logging.getLogger("network_traffic_analyzer.scada_detector")

# OT Protocol Definitions for fingerprinting
SCADA_PROTOCOLS = {
    "Modbus TCP": {
        "ports": [502],
        "risk": "HIGH",
        "description": "Modbus TCP — SCADA/PLC communication protocol"
    },
    "DNP3": {
        "ports": [20000],
        "risk": "HIGH",
        "description": "DNP3 — Electric utility SCADA protocol"
    },
    "IEC 104": {
        "ports": [2404],
        "risk": "HIGH",
        "description": "IEC 60870-5-104 — Power grid control protocol"
    },
    "EtherNet/IP": {
        "ports": [44818, 2222],
        "risk": "MEDIUM",
        "description": "EtherNet/IP — Industrial Ethernet (Rockwell/Allen-Bradley)"
    },
    "BACnet": {
        "ports": [47808],
        "risk": "MEDIUM",
        "description": "BACnet — Building automation protocol"
    },
    "Siemens S7": {
        "ports": [102],
        "risk": "HIGH",
        "description": "S7comm — Siemens SIMATIC PLC protocol"
    },
    "FINS": {
        "ports": [9600],
        "risk": "MEDIUM",
        "description": "OMRON FINS — Factory automation protocol"
    },
    "OPC-DA": {
        "ports": [135],
        "risk": "MEDIUM",
        "description": "OPC-DA — OLE for Process Control (legacy)"
    },
    "Profinet": {
        "ports": [34962, 34963, 34964],
        "risk": "MEDIUM",
        "description": "Profinet — Siemens industrial Ethernet"
    }
}

def _is_private_ip(ip: str) -> bool:
    """
    Checks if an IP address belongs to RFC1918 private ranges or loopback.

    Args:
        ip (str): The IP address string to check.

    Returns:
        bool: True if the IP is private/internal, False otherwise.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except (ValueError, AttributeError):
        return False

class SCADADetector:
    """
    Specialized engine for detecting Industrial Control Systems (ICS/OT) traffic.

    Uses port fingerprinting and behavioral rules to identify SCADA protocols
    and suspicious communication patterns in industrial networks.
    """

    def __init__(self):
        """
        Initializes the SCADADetector with protocol signatures and rules.
        """
        self.protocols = SCADA_PROTOCOLS
        self.detection_count = 0
        self.logger = logging.getLogger("network_traffic_analyzer.scada_detector")
        
        self.logger.info(
            f"SCADA Detector initialized with {len(self.protocols)} protocol signatures"
        )

    def analyze(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Analyzes a packet for OT protocol signatures or anomalies.

        Args:
            packet (Dict[str, Any]): Dictionary containing packet metadata.

        Returns:
            Optional[Dict[str, Any]]: An alert dictionary if a detection occurs, 
            otherwise None.
        """
        dst_port = packet.get("dst_port")
        src_port = packet.get("src_port")
        
        if dst_port is None and src_port is None:
            return None

        # Check for known OT protocols first
        known_alert = self._check_known_protocol(packet)
        if known_alert:
            return known_alert

        # Check for suspicious combinations/anomalies
        anomaly_alert = self._check_suspicious_combination(packet)
        if anomaly_alert:
            return anomaly_alert

        return None

    def _check_known_protocol(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Checks if the packet ports match known SCADA/OT protocols.

        Args:
            packet (Dict[str, Any]): Packet metadata.

        Returns:
            Optional[Dict[str, Any]]: Alert dictionary if protocol matched.
        """
        dst_port = packet.get("dst_port")
        src_port = packet.get("src_port")
        
        for protocol_name, info in self.protocols.items():
            if dst_port in info["ports"] or src_port in info["ports"]:
                self.detection_count += 1
                
                self.logger.warning(
                    f"OT Protocol detected: {protocol_name} on port {dst_port} "
                    f"from {packet.get('src_ip')}"
                )
                
                return {
                    "alert_type": f"OT_PROTOCOL_{protocol_name.upper().replace(' ', '_')}",
                    "severity": info["risk"],
                    "description": (
                        f"{protocol_name} traffic detected: "
                        f"{packet.get('src_ip')}:{src_port} -> "
                        f"{packet.get('dst_ip')}:{dst_port} | "
                        f"{info['description']}"
                    )
                }
        
        return None

    def _check_suspicious_combination(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Detects protocol anomalies or unauthorized access patterns.

        Checks for Modbus over UDP and external access to Siemens S7comm.

        Args:
            packet (Dict[str, Any]): Packet metadata.

        Returns:
            Optional[Dict[str, Any]]: Alert dictionary if anomaly detected.
        """
        dst_port = packet.get("dst_port")
        protocol = packet.get("protocol")
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")

        # Rule: Modbus TCP port (502) should NOT be used with UDP
        if dst_port == 502 and protocol == "UDP":
            self.detection_count += 1
            return {
                "alert_type": "OT_PROTOCOL_ANOMALY_MODBUS_UDP",
                "severity": "CRITICAL",
                "description": (
                    f"Modbus TCP on UDP detected: {src_ip} -> {dst_ip}:{dst_port} | "
                    "Protocol anomaly, possible evasion or misconfiguration."
                )
            }

        # Rule: Siemens S7comm (102) should only originate from internal networks
        if dst_port == 102:
            if not _is_private_ip(src_ip):
                self.detection_count += 1
                return {
                    "alert_type": "OT_PROTOCOL_UNAUTHORIZED_S7_ACCESS",
                    "severity": "CRITICAL",
                    "description": (
                        f"S7comm access from external IP {src_ip} -> {dst_ip}:{dst_port} | "
                        "Critical risk: Possible remote PLC manipulation or attack."
                    )
                }

        return None

    def get_detection_count(self) -> int:
        """
        Returns the total number of OT-related detections since initialization.

        Returns:
            int: Count of detections.
        """
        return self.detection_count

    def get_supported_protocols(self) -> List[str]:
        """
        Returns a list of OT protocols supported by this detector.

        Returns:
            List[str]: Names of supported protocols.
        """
        return list(self.protocols.keys())
