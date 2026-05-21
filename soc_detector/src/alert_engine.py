"""
Alert engine: classifies severity, writes alerts to DB and to a rolling log, and prints colored terminal alerts.
"""
import os
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from .db import DB


def setup_logger(log_path: str):
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    logger = logging.getLogger("soc_alerts")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(log_path, maxBytes=10 * 1024 * 1024, backupCount=5)
        formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


class AlertEngine:
    def __init__(self, db: DB, log_path: str = "logs/alerts.log"):
        self.db = db
        self.logger = setup_logger(log_path)

    def classify(self, meta: dict) -> str:
        """Simple severity classification based on count and thresholds.

        Returns: 'low' | 'medium' | 'high'
        """
        count = int(meta.get("count", 0))
        threshold = int(meta.get("threshold", 5))
        if count >= threshold:
            return "high"
        if count >= max(1, int(threshold / 2)):
            return "medium"
        return "low"

    def alert(self, ip: str, reason: str, meta: dict):
        severity = self.classify(meta)
        self.db.insert_alert(ip=ip, severity=severity, reason=reason)
        msg = json.dumps({"ip": ip, "severity": severity, "reason": reason, "meta": meta})
        # Log to rotating file
        self.logger.info(msg)
        # Print colored terminal alert
        self._print_terminal(severity, msg)

    def _print_terminal(self, severity: str, msg: str):
        colors = {"high": "\033[31m", "medium": "\033[33m", "low": "\033[32m"}
        reset = "\033[0m"
        color = colors.get(severity, "\033[32m")
        print(f"{color}[{severity.upper()}] {msg}{reset}")
