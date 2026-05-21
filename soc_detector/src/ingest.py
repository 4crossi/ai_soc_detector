"""Log ingestion: parse auth lines, persist events, and trigger detections."""

import sys
import re
import argparse
import os
import json
from datetime import datetime

from .db import DB
from .detector import Detector
from .alert_engine import AlertEngine

# Minimal regex for common OpenSSH auth lines
RE_FAILED = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?: port (?P<port>\d+))?")
RE_ACCEPTED = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?: port (?P<port>\d+))?")


def parse_line(line: str):
    m = RE_FAILED.search(line)
    if m:
        return "failed", m.group("user"), m.group("ip"), m.groupdict().get("port")
    m = RE_ACCEPTED.search(line)
    if m:
        return "accepted", m.group("user"), m.group("ip"), m.groupdict().get("port")
    return None, None, None, None


def ensure_db(db_path: str):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = DB(db_path)
    db.init_schema()
    return db


def process_line(line: str, db: DB, detector: Detector, alert_engine: AlertEngine):
    """Process a single auth.log line: parse, store, and run detection.

    Returns a dict with result metadata or None if line is ignored.
    """
    event, user, ip, port = parse_line(line)
    if event is None:
        return None
    ts = int(datetime.utcnow().timestamp())
    outcome = "failed" if event == "failed" else "success"
    db.insert_attempt(ip=ip, user=user, outcome=outcome, port=port, ts=ts)
    if outcome == "failed":
        is_attack, meta = detector.check_bruteforce(ip)
        if is_attack:
            reason = f"brute-force: {meta['count']} failed in {meta['window_minutes']}m"
            alert_engine.alert(ip=ip, reason=reason, meta=meta)
        elif meta["count"] >= int(meta["threshold"] / 2):
            alert_engine.alert(ip=ip, reason=f"potential brute: count={meta['count']}", meta=meta)
        return {"ip": ip, "outcome": outcome, "meta": meta}
    return {"ip": ip, "outcome": outcome}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init-db", action="store_true")
    parser.add_argument("--config", default=os.path.join(os.path.dirname(os.path.dirname(__file__)), "configs", "config.json"))
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = json.load(f)
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), cfg.get("db_path", "data/soc_events.db"))
    db = ensure_db(db_path)
    if args.init_db:
        print(f"Initialized DB at {db_path}")
        return

    detector = Detector(db)
    alert_engine = AlertEngine(db=db, log_path=os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "alerts.log"))

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            process_line(line, db, detector, alert_engine)
        except Exception:
            # keep running on parse errors
            continue


if __name__ == "__main__":
    main()
