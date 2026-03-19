# Network Traffic Analyzer — OT/ICS Protocol Detection

> A real-time network packet analysis system with deep inspection for Operational Technology (OT) and Industrial Control System (ICS) protocols. Detects SCADA traffic, tracks TCP/UDP sessions, and visualizes network behavior through a modern web dashboard.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-2.3+-green?style=flat-square&logo=flask)
![Scapy](https://img.shields.io/badge/Scapy-2.5+-orange?style=flat-square)
![SQLite](https://img.shields.io/badge/SQLite-WAL_Mode-yellow?style=flat-square&logo=sqlite)
![Chart.js](https://img.shields.io/badge/Chart.js-4.x-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [OT/ICS Protocol Detection](#otics-protocol-detection)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Setup & Installation](#setup--installation)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Dashboard](#dashboard)
- [Future Roadmap](#future-roadmap)

---

## Overview

Most network analyzers are built for IT environments. This tool is designed with OT/ICS awareness — it fingerprints industrial protocols like Modbus TCP, DNP3, IEC 104, and Siemens S7comm that run critical infrastructure including power grids, water treatment plants, and manufacturing systems.

**What makes this different from Wireshark or a generic packet sniffer:**

- Purpose-built SCADA protocol fingerprinting engine with 9 OT protocol signatures
- Behavioral anomaly detection — flags Modbus on UDP, external S7comm access, and other OT-specific attack patterns
- 5-tuple TCP/UDP flow tracking with session lifecycle management (FIN/RST detection)
- Thread-safe capture pipeline: Scapy → Queue → Analyzer → SQLite → REST API → Dashboard
- Real-time web dashboard with protocol distribution charts, top talkers, and live alert feed

This project demonstrates end-to-end network security engineering — from raw packet capture at Layer 3/4 to actionable OT threat detection in a SOC-ready interface.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Network Interface                           │
│              Raw packets via Scapy sniff()                      │
└────────────────────────┬────────────────────────────────────────┘
                         │ daemon thread
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    capture.py                                   │
│   PacketCapture — BPF filter, IP/TCP/UDP/ICMP extraction        │
│   TCP flags extraction (FIN/RST for flow termination)           │
│   Thread-safe queue.Queue(maxsize=1000)                         │
└────────────────────────┬────────────────────────────────────────┘
                         │ packet dicts
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                    analyzer.py                                  │
│   TrafficAnalyzer — consumes queue every 1 second              │
│   Updates protocol stats, top talkers, byte counts             │
│   Calls SCADADetector per packet                               │
│   Batch-writes protocol stats to DB                            │
└──────────┬──────────────────────┬──────────────────────────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐   ┌─────────────────────────────────────────┐
│  flow_tracker.py │   │           scada_detector.py             │
│  FlowTracker     │   │   SCADADetector                         │
│  5-tuple session │   │   9 OT protocol signatures              │
│  tracking        │   │   Port fingerprinting                   │
│  FIN/RST close   │   │   Anomaly rules (Modbus/UDP, S7/extern) │
│  Timeout expire  │   │   Returns alert dict or None            │
└──────────┬───────┘   └──────────────────────┬──────────────────┘
           │                                   │
           └──────────────┬────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    database.py                                  │
│   DatabaseManager — SQLite WAL mode                            │
│   flows table — 5-tuple + bytes + duration                     │
│   protocols table — UPSERT aggregation per protocol            │
│   alerts table — OT detections + severity                      │
│   Indexes on timestamp, protocol, src_ip, dst_ip               │
└────────────────────────┬────────────────────────────────────────┘
                         │ REST API
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                      app.py                                     │
│   Flask REST API — 9 endpoints                                 │
│   CSP headers, CORS, environment-based config                  │
│   Capture start/stop via API                                   │
└────────────────────────┬────────────────────────────────────────┘
                         │ polling every 3-5s
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│                  frontend/index.html                            │
│   Single-page dashboard — Overview / Flows / Alerts tabs       │
│   Chart.js doughnut — protocol distribution                    │
│   Top talkers bandwidth bars                                   │
│   OT protocol signatures panel                                 │
│   Live alert feed with severity badges                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

### Packet Capture Engine
- **Live capture** via Scapy `sniff()` in a daemon thread — completely non-blocking
- **BPF filter support** — pass any Berkeley Packet Filter expression to narrow capture scope
- **Protocol extraction** — TCP, UDP, ICMP, and raw IP protocol numbers
- **Port extraction** — src/dst ports for TCP and UDP flows
- **TCP flag extraction** — FIN and RST flags passed to flow tracker for session close detection
- **Queue-based pipeline** — `queue.Queue(maxsize=1000)` prevents memory exhaustion under high traffic
- **Graceful shutdown** — `threading.Event` stop signal with 5-second join timeout

### Flow Tracking
- **5-tuple session tracking** — (src_ip, src_port, dst_ip, dst_port, protocol)
- **Session lifecycle** — ACTIVE state until FIN/RST received or timeout expires
- **Configurable timeout** — default 60 seconds of inactivity before flow is expired and flushed
- **Thread-safe** — `threading.Lock()` protects all dict operations
- **Duration calculation** — precise session duration in seconds written to database on flush

### OT/ICS Protocol Detection
- **9 protocol signatures** — see [OT/ICS Protocol Detection](#otics-protocol-detection) below
- **Anomaly rules** — Modbus on UDP, S7comm from external IPs (non-RFC1918)
- **RFC1918 validation** — uses Python `ipaddress` module to classify internal vs external sources
- **Zero dependencies on Scapy** — detector works purely on packet dicts, fully testable in isolation

### Traffic Analysis
- **Real-time statistics** — total packets, total bytes, protocol distribution, top talkers
- **Batch DB writes** — protocol stats aggregated per batch before writing (reduces DB pressure)
- **Top talkers** — ranked by total bytes, both as source and destination IPs

### REST API & Dashboard
- **9 API endpoints** — status, flows, protocols, top-talkers, alerts, SCADA signatures, capture control
- **Content-Security-Policy headers** — XSS protection on the dashboard
- **Environment-based config** — interface, BPF filter, port, debug mode via env vars
- **Single-page dashboard** — Overview, Flows, and Alerts tabs with live polling

---

## OT/ICS Protocol Detection

The `SCADADetector` fingerprints traffic by destination and source port against 9 known OT protocol signatures:

| Protocol | Port(s) | Risk | Description |
|----------|---------|------|-------------|
| Modbus TCP | 502 | HIGH | SCADA/PLC communication — no auth, no encryption |
| DNP3 | 20000 | HIGH | Electric utility SCADA protocol |
| IEC 104 | 2404 | HIGH | IEC 60870-5-104 — power grid control |
| Siemens S7 | 102 | HIGH | S7comm — Siemens SIMATIC PLC protocol |
| EtherNet/IP | 44818, 2222 | MEDIUM | Industrial Ethernet (Rockwell/Allen-Bradley) |
| BACnet | 47808 | MEDIUM | Building automation protocol |
| FINS | 9600 | MEDIUM | OMRON FINS — factory automation |
| OPC-DA | 135 | MEDIUM | OLE for Process Control (legacy) |
| Profinet | 34962-34964 | MEDIUM | Siemens industrial Ethernet |

### Anomaly Detection Rules

| Rule | Trigger | Severity |
|------|---------|----------|
| Modbus over UDP | Port 502 on UDP protocol | CRITICAL |
| External S7comm access | Port 102 from non-RFC1918 source IP | CRITICAL |

Both rules flag conditions that should never occur in a legitimate ICS environment and are strong indicators of reconnaissance, evasion, or active attack.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Packet Capture | Scapy 2.5+ | Raw packet capture, protocol layer parsing |
| Backend | Python 3.8+, Flask 2.3+ | REST API, request routing, static serving |
| Database | SQLite with WAL mode | Concurrent read/write, flow/alert persistence |
| OT Detection | Python ipaddress module | RFC1918 classification, protocol fingerprinting |
| Frontend | HTML5, CSS3, JavaScript (vanilla) | Single-page dashboard, no frameworks |
| Charts | Chart.js 4.x | Protocol distribution doughnut chart |
| Fonts | Inter + JetBrains Mono | UI text + monospace for IPs/ports/values |
| Security | Flask-CORS, CSP Headers | Cross-origin protection, XSS prevention |
| Platform | Npcap (Windows) / libpcap (Linux) | Kernel-level packet capture driver |

---

## Project Structure

```
network-traffic-analyzer/
├── backend/
│   ├── app.py                  # Flask application, API routes, CSP headers
│   ├── capture.py              # Scapy packet capture, queue pipeline, TCP flags
│   ├── analyzer.py             # Packet processing, stats aggregation, DB writes
│   ├── flow_tracker.py         # 5-tuple session tracking, FIN/RST handling
│   ├── scada_detector.py       # OT protocol fingerprinting, anomaly rules
│   ├── database.py             # SQLite WAL manager, schema, CRUD operations
│   └── requirements.txt        # Python dependencies
├── frontend/
│   └── index.html              # Single-page dashboard (CSS + JS embedded)
├── pcaps/                      # Directory for saved .pcap files (optional)
├── screenshots/                # Dashboard screenshots for documentation
├── .gitignore
└── README.md
```

---

## Setup & Installation

### Prerequisites

- Python 3.8+
- **Windows:** [Npcap](https://npcap.com/#download) — install with default options, reboot terminal after
- **Linux/Mac:** libpcap — usually pre-installed (`sudo apt install libpcap-dev` if not)
- Administrator/root privileges required for packet capture

### 1. Clone the repository

```bash
git clone https://github.com/Lohith115/network-traffic-analyzer.git
cd network-traffic-analyzer
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 4. Find your network interface name

**Windows** — Scapy uses NPF GUIDs, not friendly names:

```bash
python -c "
from scapy.all import get_if_list, get_if_addr
for iface in get_if_list():
    try:
        ip = get_if_addr(iface)
        print(f'{ip}  ->  {iface}')
    except:
        pass
"
```

Find the line with your local IP (e.g. `192.168.x.x`) — copy the full `\Device\NPF_{...}` string.

**Linux/Mac:**

```bash
ip link show      # or: ifconfig
# Use names like eth0, wlan0, ens33
```

### 5. Start the server

```bash
# Run from backend/ directory — requires admin/root
# Windows: Run terminal as Administrator
# Linux: sudo python3 app.py

python app.py
```

Dashboard available at: `http://localhost:5000`

### 6. Start capture

Open the dashboard, paste your interface name into the interface field, click **Start Capture**.

Or via environment variable to auto-start:

```bash
CAPTURE_INTERFACE="eth0" python app.py        # Linux
set CAPTURE_INTERFACE=\Device\NPF_{...} && python app.py   # Windows
```

---

## Usage

### Dashboard Controls

**Starting capture:**
1. Paste interface name into the interface input field (top right)
2. Click **Start Capture**
3. Status indicator turns green with pulse animation
4. Stats begin updating every 3 seconds

**Tabs:**
- **Overview** — stat cards, protocol distribution chart, top talkers, OT signature panel
- **Flows** — live table of network flows with src/dst IP:port, protocol, bytes, duration
- **Alerts** — OT protocol detections and anomalies with severity badges

### BPF Filters (optional)

Pass filters via `BPF_FILTER` environment variable to narrow capture scope:

```bash
BPF_FILTER="port 502" python app.py          # Modbus TCP only
BPF_FILTER="host 192.168.1.100" python app.py # Single host
BPF_FILTER="tcp" python app.py               # TCP only
```

### Testing OT Detection

To verify Modbus detection without a real PLC, send a test packet:

```bash
# In a second terminal (requires Scapy + admin rights)
python -c "
from scapy.all import IP, TCP, send
send(IP(dst='127.0.0.1')/TCP(dport=502, flags='S'))
"
```

Check the Alerts tab — a Modbus TCP detection alert should appear within 3 seconds.

---

## API Reference

### GET `/api/status`

```json
{
  "capture_running": true,
  "queue_size": 12,
  "active_flows": 47,
  "total_packets": 15832,
  "total_bytes": 24831920,
  "uptime_seconds": 342.7
}
```

### GET `/api/protocols`

```json
[
  {"protocol": "TCP", "packet_count": 12400, "bytes": 19200000},
  {"protocol": "UDP", "packet_count": 3200, "bytes": 5400000},
  {"protocol": "ICMP", "packet_count": 232, "bytes": 231920}
]
```

### GET `/api/top-talkers?limit=10`

```json
[
  {"ip": "192.168.1.105", "bytes": 8240000},
  {"ip": "192.168.1.1",   "bytes": 6100000}
]
```

### GET `/api/alerts?limit=20&severity=HIGH`

```json
[
  {
    "id": 1,
    "timestamp": "2026-03-19T14:23:01",
    "alert_type": "OT_PROTOCOL_MODBUS_TCP",
    "severity": "HIGH",
    "description": "Modbus TCP traffic detected: 10.0.0.5:54321 -> 192.168.1.10:502 | Modbus TCP — SCADA/PLC communication protocol"
  }
]
```

### POST `/api/capture/start`

```json
// Request
{"interface": "eth0", "bpf_filter": ""}

// Response 200
{"status": "started", "interface": "eth0"}

// Response 409 — already running
{"error": "Capture already running"}

// Response 403 — insufficient privileges
{"error": "Root/admin privileges required"}
```

### POST `/api/capture/stop`

```json
{"status": "stopped", "total_packets": 15832}
```

### GET `/api/scada/protocols`

```json
[
  {"name": "Modbus TCP", "ports": [502], "risk": "HIGH",
   "description": "Modbus TCP — SCADA/PLC communication protocol"},
  {"name": "DNP3", "ports": [20000], "risk": "HIGH",
   "description": "DNP3 — Electric utility SCADA protocol"}
]
```

---

## Dashboard

The dashboard is a single-page application served directly by Flask with zero external dependencies beyond Chart.js.

**Overview tab** — real-time stat cards (total packets, bytes, active flows, uptime), protocol distribution doughnut chart, top talkers bandwidth visualization, and OT protocol signature reference panel.

**Flows tab** — live table of network flows with colored protocol badges, formatted byte values, session duration, and src/dst IP:Port in monospace font.

**Alerts tab** — severity-filtered alert feed. Each alert card shows the MITRE-adjacent alert type, severity badge, description with highlighted IP addresses, and an OT/ICS tag for industrial protocol detections.

---

## Future Roadmap

- [ ] Payload inspection — deep packet inspection for Modbus function code analysis
- [ ] PCAP export — save captured sessions to `.pcap` format for Wireshark analysis
- [ ] MITRE ATT&CK for ICS mapping — link each OT alert to specific ICS tactics/techniques
- [ ] Geo-IP visualization — map attacker source IPs on a world map
- [ ] Docker deployment — containerized setup with `docker-compose`
- [ ] WebSocket updates — replace polling with server-sent events for true real-time
- [ ] DNP3 and IEC 104 payload parsing — extract function codes and data objects
- [ ] Alert export — CSV/PDF incident reports from the Alerts tab

---

## Author

**T Lohith** — M.Tech Networks & Cybersecurity, Amity University Gurugram

Specializing in OT/ICS security and Blue Team operations. This project is part of a cybersecurity portfolio targeting SOC Analyst and Security Engineer roles with a focus on critical infrastructure protection.

- GitHub: [github.com/Lohith115](https://github.com/Lohith115)
- LinkedIn: [linkedin.com/in/its-lohith-944909318](https://linkedin.com/in/its-lohith-944909318)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
