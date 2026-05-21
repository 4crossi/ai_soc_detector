"""
Advanced detection rules for Phase 5.

Includes port scan detection and sudo/privilege escalation detection.
"""
import re
from datetime import datetime, timedelta
from .db import DB


RE_PORT = re.compile(r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port (?P<port>\d+)")
RE_SUDO = re.compile(r"sudo:.*session opened for user (?P<user>\S+) by (?P<actor>\S+)")


class AdvancedDetector:
    def __init__(self, db: DB):
        self.db = db

    def detect_portscan(self, ip: str, window_minutes: int = 1, port_threshold: int = 10) -> (bool, dict):
        """Detect port scan by counting unique destination ports for an IP in recent window."""
        cutoff = int((datetime.utcnow() - timedelta(minutes=window_minutes)).timestamp())
        conn = self.db.connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT port) FROM attempts WHERE ip=? AND ts>=? AND port IS NOT NULL", (ip, cutoff))
        row = cur.fetchone()
        unique_ports = row[0] if row else 0
        meta = {'ip': ip, 'unique_ports': unique_ports, 'window_minutes': window_minutes}
        return (unique_ports >= port_threshold), meta

    def detect_sudo_escalation(self, window_minutes: int = 10) -> list:
        """Return list of sudo escalation events from alerts/attempts where sudo session opened."""
        conn = self.db.connect()
        cur = conn.cursor()
        cur.execute("SELECT ts, ip, user, outcome FROM attempts ORDER BY ts DESC LIMIT 1000")
        rows = cur.fetchall()
        events = []
        for r in rows:
            line = ' '.join(map(str, r))
            m = RE_SUDO.search(line)
            if m:
                events.append({'user': m.group('user'), 'actor': m.group('actor'), 'ts': r[0]})
        return events
