"""
Detection logic for SOC detector Phase 1.

Provides brute-force detection by counting failed attempts in a sliding window.
"""
from typing import Tuple
import json
import os

from .db import DB


def load_config():
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "configs", "config.json")
    with open(cfg_path, "r") as f:
        return json.load(f)


class Detector:
    def __init__(self, db: DB):
        self.db = db
        self.cfg = load_config()

    def check_bruteforce(self, ip: str) -> Tuple[bool, dict]:
        """Return (is_bruteforce, metadata).

        Checks the number of failed attempts for `ip` in the configured window and returns a decision.
        """
        window = int(self.cfg.get("bruteforce_window_minutes", 5))
        threshold = int(self.cfg.get("bruteforce_threshold", 5))
        count = self.db.count_failed_since(ip, window)
        meta = {"ip": ip, "window_minutes": window, "count": count, "threshold": threshold}
        is_attack = count >= threshold
        return is_attack, meta
