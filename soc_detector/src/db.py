"""
SQLite helper for SOC detector.

Provides initialization, insert, and query helpers used by the ingestion and detection modules.
"""
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional


class DB:
    """Simple thread-safe SQLite wrapper.

    Methods:
    - init(schema): create tables
    - insert_attempt(ip,user,outcome,timestamp)
    - count_failed_since(ip, minutes)
    - insert_alert(...)
    """

    def __init__(self, path: str):
        self.path = path
        self.lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self):
        with self.lock:
            if self._conn is None:
                self._conn = sqlite3.connect(self.path, check_same_thread=False)
                self._conn.row_factory = sqlite3.Row
        return self._conn

    def init_schema(self):
        """Create the tables used by Phase 1.

        - attempts: stores each observed auth event
        - alerts: stores generated alerts
        """
        conn = self.connect()
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    user TEXT,
                    outcome TEXT,
                    port TEXT,
                    ts INTEGER NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                severity TEXT,
                reason TEXT,
                ts INTEGER NOT NULL
            )
            """
        )
        conn.commit()

    def insert_attempt(self, ip: str, user: Optional[str], outcome: str, port: Optional[str] = None, ts: Optional[int] = None):
        ts = ts or int(datetime.now(tz=timezone.utc).timestamp())
        conn = self.connect()
        with self.lock:
            conn.execute("INSERT INTO attempts (ip,user,outcome,port,ts) VALUES (?,?,?,?,?)", (ip, user, outcome, port, ts))
            conn.commit()

    def count_failed_since(self, ip: str, minutes: int) -> int:
        cutoff = int((datetime.now(tz=timezone.utc) - timedelta(minutes=minutes)).timestamp())
        conn = self.connect()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(1) as cnt FROM attempts WHERE ip = ? AND outcome = 'failed' AND ts >= ?", (ip, cutoff))
        row = cur.fetchone()
        return row["cnt"] if row else 0

    def insert_alert(self, ip: str, severity: str, reason: str, ts: Optional[int] = None):
        ts = ts or int(datetime.now(tz=timezone.utc).timestamp())
        conn = self.connect()
        with self.lock:
            conn.execute("INSERT INTO alerts (ip,severity,reason,ts) VALUES (?,?,?,?)", (ip, severity, reason, ts))
            conn.commit()
