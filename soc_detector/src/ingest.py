"""
AI-Powered SOC Threat Detection System
-------------------------------------

Real-time Linux SSH authentication monitoring system.

Features:
- Real-time SSH log monitoring
- Failed login detection
- Brute-force attack detection
- IPv4 + IPv6 support
- GeoIP enrichment
- SQLite event storage
- Alert logging
- Colorized SOC alerts
- Kali Linux journalctl support

Author: Crossi
"""

import sys
import re
import argparse
import os
import sqlite3
import requests

from datetime import datetime


# ============================================================
# TERMINAL COLORS
# ============================================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ============================================================
# REGEX PATTERNS
# ============================================================

# Failed SSH authentication attempts
RE_FAILED = re.compile(
    r"(Failed password|authentication failure).*?"
    r"(?:for (?:invalid user )?(?P<user>\S+))?.*?"
    r"(?:from |rhost=)(?P<ip>[0-9a-fA-F:\.]+)"
)

# Successful SSH login
RE_ACCEPTED = re.compile(
    r"Accepted password for (?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:\.]+)"
)


# ============================================================
# DATABASE CONFIG
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DB_DIR = os.path.join(BASE_DIR, "data")

DB_PATH = os.path.join(DB_DIR, "soc_events.db")

LOG_DIR = os.path.join(BASE_DIR, "logs")

ALERT_LOG = os.path.join(LOG_DIR, "alerts.log")


# ============================================================
# CREATE REQUIRED DIRECTORIES
# ============================================================

os.makedirs(DB_DIR, exist_ok=True)

os.makedirs(LOG_DIR, exist_ok=True)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            username TEXT,
            event_type TEXT
        )
    """)

    conn.commit()

    conn.close()

    print(f"{GREEN}[+] Database initialized{RESET}")

    print(f"{CYAN}[DB] {DB_PATH}{RESET}")


# ============================================================
# SAVE EVENT
# ============================================================

def save_event(ip, username, event_type):

    conn = sqlite3.connect(DB_PATH)

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO events (
            timestamp,
            ip,
            username,
            event_type
        )
        VALUES (?, ?, ?, ?)
    """, (
        str(datetime.now()),
        ip,
        username,
        event_type
    ))

    conn.commit()

    conn.close()


# ============================================================
# SAVE ALERTS
# ============================================================

def save_alert(message):

    with open(ALERT_LOG, "a") as file:

        file.write(
            f"{datetime.now()} - {message}\n"
        )


# ============================================================
# GEOIP LOOKUP
# ============================================================

def get_ip_info(ip):

    # Ignore localhost/private testing
    if ip in ["127.0.0.1", "::1"]:

        return {
            "country": "Localhost",
            "city": "Local Machine",
            "isp": "Loopback"
        }

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5
        )

        data = response.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }

    except:

        return None


# ============================================================
# BRUTE FORCE TRACKER
# ============================================================

failed_attempts = {}


def detect_bruteforce(ip):

    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    return failed_attempts[ip]


# ============================================================
# PARSE SSH LOGS
# ============================================================

def parse_line(line):

    # Failed logins
    failed_match = RE_FAILED.search(line)

    if failed_match:

        return (
            "failed",
            failed_match.group("user"),
            failed_match.group("ip")
        )

    # Successful logins
    accepted_match = RE_ACCEPTED.search(line)

    if accepted_match:

        return (
            "accepted",
            accepted_match.group("user"),
            accepted_match.group("ip")
        )

    return (None, None, None)


# ============================================================
# PROCESS LOG EVENTS
# ============================================================

def process_line(line):

    event, user, ip = parse_line(line)

    # Ignore unrelated logs
    if event is None:
        return

    print(f"\n{BLUE}======================================{RESET}")

    print(f"{YELLOW}[SSH EVENT DETECTED]{RESET}")

    print(f"{GREEN}[EVENT]{RESET} {event}")

    print(f"{GREEN}[USER ]{RESET} {user}")

    print(f"{GREEN}[IP   ]{RESET} {ip}")

    print(f"{BLUE}======================================{RESET}")

    # Save event
    save_event(ip, user, event)

    # --------------------------------------------------------
    # FAILED LOGIN HANDLING
    # --------------------------------------------------------

    if event == "failed":

        print(
            f"{RED}[ALERT]{RESET} "
            f"Failed SSH login detected"
        )

        attempts = detect_bruteforce(ip)

        print(
            f"{YELLOW}[INFO]{RESET} "
            f"Failed Attempts: {attempts}"
        )

        # GeoIP Enrichment
        info = get_ip_info(ip)

        if info:

            print(
                f"{CYAN}[GEO]{RESET} "
                f"{info['country']} | "
                f"{info['city']} | "
                f"{info['isp']}"
            )

        # Brute Force Threshold
        if attempts >= 5:

            critical_message = (
                f"Brute Force Attack Detected "
                f"from {ip}"
            )

            print(
                f"{RED}[CRITICAL]{RESET} "
                f"{critical_message}"
            )

            save_alert(critical_message)

    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

    elif event == "accepted":

        print(
            f"{GREEN}[SUCCESS]{RESET} "
            f"Successful SSH login from {ip}"
        )


# ============================================================
# MAIN APPLICATION
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--init-db",
        action="store_true",
        help="Initialize database"
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # DATABASE INIT
    # --------------------------------------------------------

    if args.init_db:

        init_db()

        return

    # --------------------------------------------------------
    # START ENGINE
    # --------------------------------------------------------

    print(
        f"{GREEN}[+] SOC Threat Detection Started{RESET}"
    )

    print(
        f"{GREEN}[+] Waiting for SSH logs...{RESET}\n"
    )

    # --------------------------------------------------------
    # LIVE LOG STREAM
    # --------------------------------------------------------

    for raw in sys.stdin:

        line = raw.strip()

        if not line:
            continue

        print(f"{CYAN}[RAW LOG]{RESET} {line}")

        try:

            process_line(line)

        except Exception as error:

            print(
                f"{RED}[ERROR]{RESET} {error}"
            )

            continue


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
