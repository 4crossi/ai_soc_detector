# AI-Powered SOC Threat Detection Platform

A real-time Security Operations Center (SOC) monitoring and threat detection platform designed for Linux environments.

This project simulates core SOC and SIEM workflows by ingesting SSH authentication logs, detecting suspicious activity, enriching attacker information with GeoIP intelligence, storing security events in SQLite, and visualizing threats through a live Flask-based dashboard.

The platform is built for:
- Blue Team security workflows
- Detection engineering practice
- Linux log analysis
- Security monitoring simulations
- SOC analyst training environments

---

# Features

- Real-time Linux SSH authentication log monitoring
- Failed login and brute-force attack detection
- Successful login tracking
- Invalid SSH user detection
- SSH timeout event monitoring
- GeoIP enrichment for attacker IPs
- IPv4 and IPv6 support
- SQLite-based event storage
- Real-time Flask dashboard
- Live threat feed visualization
- Top attacker IP tracking
- Bash-based log watcher automation
- REST API support
- Simulated attack traffic generation
- Lightweight SOC/SIEM simulation environment

---

# Architecture

```text
Linux SSH Logs
        ↓
watch_auth.sh
        ↓
ingest.py
        ↓
SQLite Database
        ↓
Flask REST APIs
        ↓
SOC Dashboard
```

# Screenshots
SOC Dashboard
<img width="1600" height="769" alt="live_detection" src="https://github.com/user-attachments/assets/6eff9aca-6cea-4ca3-a7a4-d26f1d96d295" />
Terminal Detection Engine
<img width="1600" height="769" alt="dashboard" src="https://github.com/user-attachments/assets/8d5395b1-d714-4f50-b46b-64bf81cfb87f" />

# Project Structure
```bash
soc_detector/
│
├── soc_detector/
│   ├── src/
│   │   ├── ingest.py
│   │   ├── web.py
│   │   └── __init__.py
│   │
│   ├── bin/
│   │   ├── watch_auth.sh
│   │   └── simulate_auth.sh
│   │
│   ├── data/
│   │   └── soc_events.db
│   │
│   ├── logs/
│   │   └── alerts.log
│   │
│   ├── configs/
│   │   └── config.json
│   │
│   └── requirements.txt
│
├── screenshots/
├── README.md
└── requirements.txt
```
Detection Capabilities

The platform currently supports detection and monitoring of:

SSH brute-force attacks
Failed authentication attempts
Successful SSH logins
Invalid user enumeration attempts
Authentication timeout events
Repeated attacker IP correlation
GeoIP-based attacker origin tracking
Live suspicious activity monitoring

# Quick start (Linux)

1. Create virtualenv and install deps

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r soc_detector/requirements.txt
```

2. Initialize DB

```bash
python3 soc_detector/src/ingest.py --init-db
```

3. Test with simulated logs (no root needed)

```bash
bash soc_detector/bin/simulate_auth.sh
```

4. Run real-time watcher (requires read access to /var/log/auth.log)

```bash
sudo bash soc_detector/bin/watch_auth.sh
```

5. Run the dashboard

```bash
python3 soc_detector/src/web.py
# open http://localhost:5000
```
```bash
Open browser:
http://localhost:5000
```

# Simulated Attack Testing

```Generate simulated SSH attack traffic:

for i in {1..20}
do

echo "Failed password for invalid user admin$i from 192.168.1.$i port 22 ssh2"

echo "Accepted password for kali$i from 10.0.0.$i port 22 ssh2"

done | python3 -m soc_detector.src.ingest
Example Threat Events
```
Security Monitoring Workflow
SSH Authentication Logs
        ↓
Live Log Monitoring
        ↓
Event Parsing
        ↓
Threat Detection
        ↓
GeoIP Enrichment
        ↓
Database Storage
        ↓
Dashboard Visualization
Future Improvements

Planned future enhancements include:

Threat intelligence integration
VirusTotal API integration
AbuseIPDB enrichment
Automatic IP blocking
Port scan detection
ML-based anomaly detection
Docker deployment support
ELK Stack integration
Multi-source log ingestion
Web attack detection
Real-time websocket dashboard updates
Use Cases

This project can be used for:

SOC analyst practice
Detection engineering learning
Linux log monitoring simulations
Security operations demonstrations
Blue team portfolio projects
Cybersecurity internship showcases
