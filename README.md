# NetGuard 🛡️

Real-time network traffic monitor with AI-powered alert analysis and automated vulnerability scanning.

NetGuard captures live network packets, detects anomalous behavior patterns, automatically counter-scans suspicious IPs, and uses Claude AI to provide natural language explanations and actionable recommendations for each security alert.

---

## Features

- **Live packet capture** — intercepts all network traffic on the host interface in real time
- **Anomaly detection** — identifies port scans and brute force attacks using time-window analysis
- **Automated counter-scan** — when a port scan is detected, automatically scans the attacker's IP for exposed services
- **AI-powered analysis** — sends alerts + counter-scan results to Claude API for natural language explanation, risk assessment, and recommended actions
- **Web dashboard** — real-time interface with WebSocket updates, traffic feed, and alert panel with attacker profile

---

## Architecture
```text
netguard/
├── capture_rs/                  # Rust — packet capture module
│   ├── src/main.rs              # raw byte parsing via libpcap
│   └── Cargo.toml
├── vuln_scanner/                # Rust — TCP port scanner
│   ├── src/main.rs              # async concurrent scanning with Tokio
│   └── Cargo.toml
├── src/
│   ├── capture/
│   │   ├── sniffer.py           # original Python capture (reference)
│   │   └── sniffer_rs.py        # Python ↔ Rust bridge (subprocess + JSON)
│   ├── analyzer/
│   │   ├── detector.py          # anomaly detection engine
│   │   └── scanner_integration.py  # counter-scan trigger
│   ├── ai/
│   │   └── analizador.py        # Claude API integration
│   └── dashboard/
│       ├── app.py               # FastAPI server + WebSocket
│       └── static/
│           └── index.html       # real-time web interface
├── .env.example
└── README.md
```

### How it works

1. **Capture** — a Rust binary hooks into the network interface via libpcap and parses raw bytes for each IP packet. Output is streamed as JSON via stdout to the Python process.

2. **Detection** — every 10 seconds, the detector analyzes traffic within a 60-second sliding window per source IP:
   - **Port scan**: flags IPs contacting 8+ distinct ports
   - **Brute force**: flags IPs making 5+ connections to the same port

3. **Counter-scan** — when a PORT_SCAN alert fires, NetGuard automatically launches the Rust vulnerability scanner against the attacker's IP, scanning ports 1-1024 with 200 concurrent connections. Results are attached to the alert context.

4. **AI Analysis** — each alert is sent to Claude with structured context: alert type, IP, severity, scanned ports, and counter-scan results. Claude returns a formatted response covering analysis, risk, recommended actions, false positive evaluation, and attacker profile when counter-scan data is available.

5. **Dashboard** — FastAPI serves a WebSocket endpoint that pushes live packet updates every 2 seconds and broadcasts alerts instantly. Each alert card shows the AI analysis and counter-scan results.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Packet capture | Rust + libpcap | Raw packet interception, zero-overhead parsing |
| Port scanner | Rust + Tokio | Async concurrent TCP scanning |
| Python bridge | subprocess + JSON stdout | IPC between Rust and Python |
| Anomaly detection | Python stdlib | Time-window analysis, pattern matching |
| AI integration | Anthropic Claude API (Haiku) | Natural language alert analysis |
| Web server | FastAPI + Uvicorn | Async REST API + WebSocket server |
| Frontend | Vanilla JS + WebSocket | Real-time DOM updates |
| Environment | WSL2 + Python venv | Linux networking stack on Windows |

---

## Detected Threats

### Port Scan
Triggered when a single source IP contacts 8+ distinct ports within 60 seconds. Maps to **reconnaissance** — stage 1 of the Cyber Kill Chain. Automatically triggers a counter-scan of the attacker IP.

### Brute Force
Triggered when a single source IP makes 5+ TCP connections to the same port within 60 seconds. Maps to **exploitation** — stage 4 of the Cyber Kill Chain. Covers SSH (high severity), RDP, FTP, HTTP, HTTPS, and database ports.

---

## Vulnerability Scanner

The standalone scanner can be used independently:
```bash
cd vuln_scanner

# Scan a specific host and port range
./target/release/vuln_scanner --host 192.168.1.1 --start 1 --end 1024

# Custom timeout and concurrency
./target/release/vuln_scanner --host 8.8.8.8 --start 1 --end 1024 --timeout 2000 --concurrencia 200
```

Output includes open ports, identified services, and latency. JSON output is available for pipeline integration.

**Example output:**
NetGuard Scanner — escaneando 8.8.8.8:1-1024
Timeout: 2000ms | Concurrencia: 200 puertos simultáneos
3 puertos abiertos encontrados:
PUERTO   ESTADO       SERVICIO        LATENCIA
53       abierto      DNS             14ms
443      abierto      HTTPS           14ms
853      abierto      DNS-over-TLS    14ms

---

## Setup

### Prerequisites

- WSL2 with Ubuntu
- Python 3.8+
- Rust 1.70+
- `libpcap` (`sudo apt install libpcap-dev`)
- Anthropic API key ([console.anthropic.com](https://console.anthropic.com))

### Installation
```bash
git clone https://github.com/TU_USUARIO/netguard.git
cd netguard

# Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install scapy fastapi uvicorn[standard] anthropic python-dotenv websockets

# Build Rust modules
cd capture_rs && cargo build --release && cd ..
cd vuln_scanner && cargo build --release && cd ..
```

### Configuration
```bash
cp .env.example .env
# Add your Anthropic API key to .env
```

`.env`:
ANTHROPIC_API_KEY=sk-ant-...

### Run
```bash
sudo ~/netguard/venv/bin/python3 -m uvicorn src.dashboard.app:app \
  --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000` in your browser.

> **Note:** root privileges are required for raw packet capture via libpcap.

---

## Active Response

NetGuard implements basic **active response** — when a port scan is detected, the system automatically:

1. Launches the Rust scanner against the attacker's IP
2. Identifies exposed services on the attacker's machine
3. Passes this intelligence to Claude for a more complete threat assessment

This mirrors how a real SOC (Security Operations Center) analyst would respond: not just logging the alert, but immediately gathering intelligence about the threat source.

---

## Concepts Applied

- **TCP/IP model** — packet parsing across layers 3 (IP, ICMP) and 4 (TCP, UDP)
- **SYN scanning** — half-open TCP scan to determine port state without completing the handshake
- **Cyber Kill Chain** — detection targets reconnaissance (port scan) and exploitation (brute force)
- **Sliding window** — time-based rate limiting mirrors Fail2ban's approach
- **Async concurrency** — Tokio runtime enables scanning hundreds of ports simultaneously
- **IPC via pipes** — Unix subprocess + stdout for Rust/Python communication
- **WebSocket vs HTTP** — protocol selection based on real-time vs request-response requirements

---

## Roadmap

- [x] Phase 1 — live packet capture with Scapy
- [x] Phase 2 — anomaly detection (port scan + brute force)
- [x] Phase 3 — Claude API integration
- [x] Phase 4 — real-time web dashboard
- [x] Phase 5 — capture module rewritten in Rust
- [x] Phase 6 — automated vulnerability scanner with active response
- [ ] PCAP export for Wireshark analysis
- [ ] IP geolocation on alerts
- [ ] Configurable detection thresholds via dashboard
- [ ] Slack / email notifications
- [ ] Service version detection (banner grabbing)

---

## Author

Built as a portfolio project combining network security fundamentals with modern systems programming (Python + Rust) and AI integration.