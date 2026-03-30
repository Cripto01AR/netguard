# NetGuard 🛡️

Real-time network traffic monitor with AI-powered alert analysis.

NetGuard captures live network packets, detects anomalous behavior patterns, and uses Claude AI to provide natural language explanations and actionable recommendations for each security alert.

---

## Features

- **Live packet capture** — intercepts all network traffic on the host interface in real time
- **Anomaly detection** — identifies port scans and brute force attacks using time-window analysis
- **AI-powered analysis** — sends alerts to Claude API for natural language explanation, risk assessment, and recommended actions
- **Web dashboard** — real-time interface with WebSocket updates, traffic feed, and alert panel

---

## Architecture
```
netguard/
├── src/
│   ├── capture/
│   │   └── sniffer.py       # Packet capture with Scapy
│   ├── analyzer/
│   │   └── detector.py      # Anomaly detection engine
│   ├── ai/
│   │   └── analizador.py    # Claude API integration
│   └── dashboard/
│       ├── app.py           # FastAPI server + WebSocket
│       └── static/
│           └── index.html   # Real-time web interface
├── .env.example
└── README.md
```

### How it works

1. **Capture** — Scapy hooks into the network interface and processes every IP packet. Each packet is parsed for source/destination IP, protocol (TCP/UDP/ICMP), and destination port.

2. **Detection** — Every 10 seconds, the detector analyzes traffic within a 60-second sliding window per source IP:
   - **Port scan**: flags IPs contacting 8+ distinct ports
   - **Brute force**: flags IPs making 5+ connections to the same port

3. **AI Analysis** — Each alert is sent to Claude with structured context (type, IP, severity, affected ports/services). Claude returns a formatted response covering analysis, risk assessment, recommended actions, and false positive evaluation.

4. **Dashboard** — FastAPI serves a WebSocket endpoint that pushes live packet updates every 2 seconds and broadcasts alerts instantly to all connected browsers.

---

## Tech Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Packet capture | [Scapy](https://scapy.net/) | Raw packet interception via libpcap |
| Anomaly detection | Python stdlib | Time-window analysis, pattern matching |
| AI integration | [Anthropic Claude API](https://docs.anthropic.com/) | Natural language alert analysis |
| Web server | [FastAPI](https://fastapi.tiangolo.com/) | Async REST API + WebSocket server |
| ASGI server | [Uvicorn](https://www.uvicorn.org/) | Production-grade async server |
| Frontend | Vanilla JS + WebSocket | Real-time DOM updates, no framework |
| Environment | WSL2 + Python venv | Linux networking stack on Windows |

---

## Detected Threats

### Port Scan
Triggered when a single source IP contacts 8 or more distinct ports within 60 seconds. Indicative of network reconnaissance — the first stage of the Cyber Kill Chain.

### Brute Force
Triggered when a single source IP makes 5 or more TCP connections to the same port within 60 seconds. Covers SSH (high severity), RDP, FTP, HTTP, HTTPS, and database ports.

---

## Setup

### Prerequisites

- WSL2 with Ubuntu
- Python 3.8+
- `libpcap` (`sudo apt install libpcap-dev`)
- Anthropic API key ([console.anthropic.com](https://console.anthropic.com))

### Installation
```bash
git clone https://github.com/TU_USUARIO/netguard.git
cd netguard
python3 -m venv venv
source venv/bin/activate
pip install scapy fastapi uvicorn[standard] anthropic python-dotenv websockets
```

### Configuration
```bash
cp .env.example .env
# Add your Anthropic API key to .env
```

`.env`:
```
ANTHROPIC_API_KEY=sk-ant-...
```

### Run
```bash
sudo ~/netguard/venv/bin/python3 -m uvicorn src.dashboard.app:app \
  --host 0.0.0.0 --port 8000 --reload
```

Open `http://localhost:8000` in your browser.

> **Note:** root privileges are required for raw packet capture via libpcap.

---

## Concepts Applied

This project was built as a practical application of networking and security fundamentals:

- **TCP/IP model** — packet parsing across layers 3 (IP, ICMP) and 4 (TCP, UDP)
- **Protocol analysis** — differentiating TCP connection patterns from UDP datagrams
- **Cyber Kill Chain** — detection targets reconnaissance (port scan) and exploitation (brute force) stages
- **Defense in depth** — time-window rate limiting mirrors Fail2ban's approach to intrusion prevention
- **WebSocket vs HTTP** — protocol selection based on real-time vs request-response requirements

---

## Roadmap

- [ ] Phase 5 — rewrite capture module in Rust for performance
- [ ] PCAP export for Wireshark analysis
- [ ] IP geolocation on alerts
- [ ] Configurable detection thresholds via dashboard
- [ ] Slack / email alert notifications

---

## Author

Built as a portfolio project combining network security fundamentals with modern Python development and AI integration.