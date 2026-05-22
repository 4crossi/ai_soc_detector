"""
AI-Powered SOC Threat Detection System
-------------------------------------

Real-time SOC monitoring engine for:
- SSH authentication logs
- Failed login detection
- Successful login detection
- Timeout detection
- Invalid user detection
- Brute-force detection
- SQLite storage
- Dashboard integration

Author: Crossi
"""

import sys
import re
import argparse
import os
import sqlite3

from datetime import datetime


# ============================================================
# COLORS
# ============================================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DB_DIR = os.path.join(BASE_DIR, "data")

DB_PATH = os.path.join(DB_DIR, "soc_events.db")

os.makedirs(DB_DIR, exist_ok=True)


# ============================================================
# REGEX PATTERNS
# ============================================================

# Failed login
RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:\.]+)"
)

# Successful login
RE_ACCEPTED = re.compile(
    r"Accepted password for "
    r"(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:\.]+)"
)

# Invalid user
RE_INVALID = re.compile(
    r"Invalid user "
    r"(?P<user>\S+) from "
    r"(?P<ip>[0-9a-fA-F:\.]+)"
)

# Timeout before authentication
RE_TIMEOUT = re.compile(
    r"Timeout before authentication.*?from "
    r"(?P<ip>[0-9a-fA-F:\.]+)"
)

# Connection closed
RE_CONNECTION_CLOSED = re.compile(
    r"Connection closed by invalid user "
    r"(?P<user>\S+) "
    r"(?P<ip>[0-9a-fA-F:\.]+)"
)


# ============================================================
# DATABASE
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

    print(f"{GREEN}[+] Database Initialized{RESET}")


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
# BRUTE FORCE TRACKER
# ============================================================

failed_attempts = {}


def detect_bruteforce(ip):

    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    return failed_attempts[ip]


# ============================================================
# PARSE LOGS
# ============================================================

def parse_line(line):

    # Failed password
    failed_match = RE_FAILED.search(line)

    if failed_match:

        return (
            "failed",
            failed_match.group("user"),
            failed_match.group("ip")
        )

    # Accepted password
    accepted_match = RE_ACCEPTED.search(line)

    if accepted_match:

        return (
            "accepted",
            accepted_match.group("user"),
            accepted_match.group("ip")
        )

    # Invalid user
    invalid_match = RE_INVALID.search(line)

    if invalid_match:

        return (
            "invalid_user",
            invalid_match.group("user"),
            invalid_match.group("ip")
        )

    # Timeout
    timeout_match = RE_TIMEOUT.search(line)

    if timeout_match:

        return (
            "timeout",
            "unknown",
            timeout_match.group("ip")
        )

    # Connection closed
    closed_match = RE_CONNECTION_CLOSED.search(line)

    if closed_match:

        return (
            "connection_closed",
            closed_match.group("user"),
            closed_match.group("ip")
        )

    return (None, None, None)


# ============================================================
# PROCESS EVENT
# ============================================================

def process_line(line):

    event, user, ip = parse_line(line)

    # Ignore unmatched logs
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
    # FAILED LOGIN
    # --------------------------------------------------------

    if event == "failed":

        print(
            f"{RED}[ALERT]{RESET} "
            f"Failed SSH Login"
        )

        attempts = detect_bruteforce(ip)

        print(
            f"{YELLOW}[INFO]{RESET} "
            f"Attempts: {attempts}"
        )

        # Brute-force detection
        if attempts >= 5:

            print(
                f"{RED}[CRITICAL]{RESET} "
                f"Brute Force Attack Detected "
                f"from {ip}"
            )

    # --------------------------------------------------------
    # SUCCESSFUL LOGIN
    # --------------------------------------------------------

    elif event == "accepted":

        print(
            f"{GREEN}[SUCCESS]{RESET} "
            f"Successful Login "
            f"from {ip}"
        )

    # --------------------------------------------------------
    # INVALID USER
    # --------------------------------------------------------

    elif event == "invalid_user":

        print(
            f"{YELLOW}[WARNING]{RESET} "
            f"Invalid User Attempt"
        )

    # --------------------------------------------------------
    # TIMEOUT
    # --------------------------------------------------------

    elif event == "timeout":

        print(
            f"{CYAN}[INFO]{RESET} "
            f"SSH Timeout Detected"
        )

    # --------------------------------------------------------
    # CONNECTION CLOSED
    # --------------------------------------------------------

    elif event == "connection_closed":

        print(
            f"{YELLOW}[INFO]{RESET} "
            f"Connection Closed"
        )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--init-db",
        action="store_true"
    )

    args = parser.parse_args()

    # Database setup
    if args.init_db:

        init_db()

        return

    print(
        f"{GREEN}[+] SOC Threat Detection Started{RESET}"
    )

    print(
        f"{GREEN}[+] Waiting for SSH logs...{RESET}\n"
    )

    # Read logs from stdin
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
# ENTRY
# ============================================================

if __name__ == "__main__":

    main()
