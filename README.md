SOC Threat Detection (Linux-ready)

This project simulates a small SOC pipeline for Linux: real-time auth log monitoring, brute-force detection, alerting, a lightweight dashboard, and ML-based anomaly detection.

Quick start (Linux)

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

Tests

```bash
python3 -m pytest -q
```

Notes

- Tests use temporary SQLite DBs and are safe to run locally.
- Use `simulate_auth.sh` for development to avoid touching production logs.
