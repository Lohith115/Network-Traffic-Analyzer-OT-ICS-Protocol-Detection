from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from scapy.all import get_if_list
from capture import PacketCapture
from analyzer import TrafficAnalyzer
from flow_tracker import FlowTracker
from scada_detector import SCADADetector, SCADA_PROTOCOLS
from database import db_manager
import os
import time
import logging
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("network_traffic_analyzer.app")

# Global state
capture_instance: Optional[PacketCapture] = None
analyzer_instance: Optional[TrafficAnalyzer] = None
flow_tracker_instance: Optional[FlowTracker] = None
app_start_time: float = time.time()

def create_app() -> Flask:
    """
    Flask application factory that initializes components and sets up routes.

    Returns:
        Flask: The configured Flask application instance.
    """
    global capture_instance, analyzer_instance, flow_tracker_instance

    app = Flask(__name__, static_folder="../frontend", static_url_path="")
    CORS(app)

    # Component Initialization
    interface = os.getenv("CAPTURE_INTERFACE", "eth0")
    bpf_filter = os.getenv("BPF_FILTER", "")
    
    capture_instance = PacketCapture(interface=interface, bpf_filter=bpf_filter)
    flow_tracker_instance = FlowTracker(db=db_manager)
    analyzer_instance = TrafficAnalyzer(capture=capture_instance, db=db_manager)

    # Content Security Policy and Headers
    @app.after_request
    def add_security_headers(response):
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com; "
            "connect-src 'self';"
        )
        response.headers['Content-Security-Policy'] = csp
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        return response

    # --- Routes ---

    @app.route("/")
    def index():
        """Serves the frontend index.html."""
        return send_from_directory(app.static_folder, "index.html")

    @app.route("/api/status", methods=["GET"])
    def get_status():
        """
        Returns the current operational status of the analyzer.
        """
        try:
            return jsonify({
                "capture_running": capture_instance.is_running() if capture_instance else False,
                "queue_size": capture_instance.get_queue_size() if capture_instance else 0,
                "active_flows": flow_tracker_instance.get_active_flow_count() if flow_tracker_instance else 0,
                "total_packets": analyzer_instance.stats["total_packets"] if analyzer_instance else 0,
                "total_bytes": analyzer_instance.stats["total_bytes"] if analyzer_instance else 0,
                "uptime_seconds": time.time() - app_start_time
            })
        except Exception as e:
            logger.error(f"Error in /api/status: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/flows", methods=["GET"])
    def get_flows():
        """
        Returns a list of recent network flows from the database.
        """
        try:
            limit = request.args.get("limit", default=100, type=int)
            flows = db_manager.get_flow_stats(limit=limit)
            return jsonify(flows)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/protocols", methods=["GET"])
    def get_protocols():
        """
        Returns protocol distribution statistics.
        """
        try:
            stats = db_manager.get_protocol_stats()
            return jsonify(stats)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/top-talkers", methods=["GET"])
    def get_top_talkers():
        """
        Returns the top IP addresses by byte volume.
        """
        try:
            limit = request.args.get("limit", default=10, type=int)
            talkers = db_manager.get_top_talkers(limit=limit)
            return jsonify(talkers)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/alerts", methods=["GET"])
    def get_alerts():
        """
        Returns a list of security alerts, optionally filtered by severity.
        """
        try:
            limit = request.args.get("limit", default=20, type=int)
            severity = request.args.get("severity")
            alerts = db_manager.get_alerts(severity=severity, limit=limit)
            return jsonify(alerts)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/capture/start", methods=["POST"])
    def start_capture():
        """
        Initializes and starts the packet capture and analysis threads.
        """
        global capture_instance, analyzer_instance
        try:
            if capture_instance and capture_instance.is_running():
                return jsonify({"error": "Capture already running"}), 409

            data = request.get_json() or {}
            interface = data.get("interface", os.getenv("CAPTURE_INTERFACE", "eth0"))
            bpf_filter = data.get("bpf_filter", "")

            # Validate interface
            if interface not in get_if_list():
                return jsonify({"error": f"Interface {interface} not found"}), 400

            # Re-initialize with new parameters if necessary
            capture_instance.interface = interface
            capture_instance.bpf_filter = bpf_filter
            
            capture_instance.start()
            analyzer_instance.start()
            
            logger.info(f"Capture started on {interface}")
            return jsonify({"status": "started", "interface": interface}), 200

        except PermissionError:
            return jsonify({"error": "Root/admin privileges required"}), 403
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        except Exception as e:
            logger.error(f"Failed to start capture: {e}")
            return jsonify({"error": str(e)}), 500

    @app.route("/api/capture/stop", methods=["POST"])
    def stop_capture():
        """
        Stops the capture and analysis threads.
        """
        try:
            if analyzer_instance:
                analyzer_instance.stop()
            if capture_instance:
                capture_instance.stop()
                count = capture_instance._packet_count
                return jsonify({"status": "stopped", "total_packets": count}), 200
            return jsonify({"error": "No capture instance found"}), 404
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scada/protocols", methods=["GET"])
    def get_scada_protocols():
        """
        Returns the list of supported OT protocol signatures.
        """
        try:
            protocols_list = []
            for name, info in SCADA_PROTOCOLS.items():
                protocols_list.append({
                    "name": name,
                    "ports": info["ports"],
                    "risk": info["risk"],
                    "description": info["description"]
                })
            return jsonify(protocols_list)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/stats/summary", methods=["GET"])
    def get_summary():
        """
        Returns a combined summary of real-time and historical statistics.
        """
        try:
            summary = analyzer_instance.get_stats() if analyzer_instance else {}
            
            # Add database counts
            summary["db_total_flows"] = db_manager.get_total_flows_count()
            summary["db_total_alerts"] = db_manager.get_total_alerts_count()
            
            return jsonify(summary)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    return app

app = create_app()

if __name__ == "__main__":
    # Load configuration from environment
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "False").lower() == "true"
    
    # Pre-start capture if configured (as per startup sequence directive)
    try:
        if capture_instance:
            capture_instance.start()
        if analyzer_instance:
            analyzer_instance.start()
        logger.info("Background threads auto-started")
    except Exception as e:
        logger.warning(f"Could not auto-start capture: {e}")

    app.run(host="0.0.0.0", port=port, debug=debug_mode)
