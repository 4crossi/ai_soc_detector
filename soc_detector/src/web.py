"""
============================================================
AI-Powered SOC Threat Detection Dashboard
============================================================

Modern Professional SOC Dashboard
Tech Stack:
- Flask
- SQLite
- REST APIs
- Live Threat Feed
- Auto Refresh Dashboard

Features:
✔ Real-time Monitoring
✔ Threat Intelligence Feed
✔ Top Attacker Tracking
✔ Live Security Events
✔ Auto Refresh
✔ Cyberpunk SOC UI
✔ Glassmorphism Design

Author: Crossi
============================================================
"""

from flask import Flask, jsonify, render_template_string
import sqlite3
import os


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

DB_PATH = os.path.join(
    BASE_DIR,
    "data",
    "soc_events.db"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_db_connection():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn


# ============================================================
# FLASK APP
# ============================================================

app = Flask(__name__)


# ============================================================
# API — SUMMARY
# ============================================================

@app.route("/api/summary")
def api_summary():

    conn = get_db_connection()

    cursor = conn.cursor()

    # --------------------------------------------
    # TOTAL EVENTS
    # --------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS total
        FROM events
    """)

    total_events = cursor.fetchone()["total"]

    # --------------------------------------------
    # FAILED EVENTS
    # --------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS failed
        FROM events
        WHERE event_type='failed'
    """)

    failed_events = cursor.fetchone()["failed"]

    # --------------------------------------------
    # SUCCESSFUL EVENTS
    # --------------------------------------------

    cursor.execute("""
        SELECT COUNT(*) AS success
        FROM events
        WHERE event_type='accepted'
    """)

    success_events = cursor.fetchone()["success"]

    # --------------------------------------------
    # TOP ATTACKER IPS
    # --------------------------------------------

    cursor.execute("""
        SELECT
            ip,
            COUNT(*) AS count
        FROM events
        GROUP BY ip
        ORDER BY count DESC
        LIMIT 5
    """)

    top_ips = []

    for row in cursor.fetchall():

        top_ips.append({
            "ip": row["ip"],
            "count": row["count"]
        })

    conn.close()

    return jsonify({
        "total_events": total_events,
        "failed_events": failed_events,
        "successful_events": success_events,
        "top_ips": top_ips
    })


# ============================================================
# API — EVENTS
# ============================================================

@app.route("/api/events")
def api_events():

    conn = get_db_connection()

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT 50
    """)

    rows = cursor.fetchall()

    events = []

    for row in rows:

        events.append({
            "id": row["id"],
            "timestamp": row["timestamp"],
            "ip": row["ip"],
            "username": row["username"],
            "event_type": row["event_type"]
        })

    conn.close()

    return jsonify(events)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def dashboard():

    html = """

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>AI SOC Dashboard</title>

    <!-- GOOGLE FONT -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap"
          rel="stylesheet">

    <style>

        :root {

            --bg: #020617;

            --card: rgba(15, 23, 42, 0.85);

            --border: #1e293b;

            --primary: #38bdf8;

            --danger: #ef4444;

            --success: #22c55e;

            --text: #e2e8f0;

            --muted: #94a3b8;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            transition: all 0.25s ease;
        }

        body {

            background:
                radial-gradient(circle at top left,
                #0f172a,
                #020617);

            color: var(--text);

            font-family: 'Inter', sans-serif;

            padding: 25px;
        }

        /* ================================================= */
        /* TOPBAR */
        /* ================================================= */

        .topbar {

            display: flex;

            justify-content: space-between;

            align-items: center;

            margin-bottom: 30px;

            padding-bottom: 15px;

            border-bottom: 1px solid var(--border);

            color: var(--muted);

            font-size: 14px;

            letter-spacing: 1px;
        }

        /* ================================================= */
        /* TITLES */
        /* ================================================= */

        h1 {

            color: var(--primary);

            font-size: 34px;

            margin-bottom: 15px;

            text-shadow:
                0 0 15px rgba(56,189,248,0.5);
        }

        h2 {

            color: var(--primary);

            margin-bottom: 15px;

            font-size: 20px;
        }

        /* ================================================= */
        /* GRID */
        /* ================================================= */

        .container {

            display: grid;

            grid-template-columns:
                repeat(auto-fit, minmax(250px, 1fr));

            gap: 20px;

            margin-bottom: 25px;
        }

        /* ================================================= */
        /* CARD */
        /* ================================================= */

        .card {

            background: var(--card);

            backdrop-filter: blur(12px);

            border: 1px solid var(--border);

            padding: 24px;

            border-radius: 18px;

            box-shadow:
                0 10px 30px rgba(0,0,0,0.3),
                inset 0 1px 0 rgba(255,255,255,0.03);
        }

        .card:hover {

            transform: translateY(-4px);

            border-color: var(--primary);
        }

        /* ================================================= */
        /* STATS */
        /* ================================================= */

        .stat-number {

            font-size: 42px;

            font-weight: 700;

            margin-top: 10px;
        }

        /* ================================================= */
        /* THREAT CARDS */
        /* ================================================= */

        .threat-card {

            background: #111827;

            border: 1px solid #1f2937;

            padding: 18px;

            margin-top: 12px;

            border-radius: 14px;
        }

        .threat-card:hover {

            transform: scale(1.02);
        }

        .critical {

            border-left: 5px solid var(--danger);
        }

        .success {

            border-left: 5px solid var(--success);
        }

        /* ================================================= */
        /* TABLE */
        /* ================================================= */

        table {

            width: 100%;

            border-collapse: collapse;

            overflow: hidden;

            border-radius: 14px;

            margin-top: 20px;
        }

        th {

            background: #0f172a;

            color: var(--primary);

            padding: 14px;

            text-align: left;

            border-bottom: 1px solid var(--border);
        }

        td {

            padding: 14px;

            border-bottom: 1px solid #162033;
        }

        tr:nth-child(even) {

            background: rgba(255,255,255,0.02);
        }

        tr:hover {

            background:
                rgba(56,189,248,0.08);
        }

        .failed {

            color: var(--danger);

            font-weight: bold;
        }

        .accepted {

            color: var(--success);

            font-weight: bold;
        }

        /* ================================================= */
        /* PULSE ANIMATION */
        /* ================================================= */

        @keyframes pulse {

            0% {
                box-shadow:
                    0 0 0 0 rgba(239,68,68,0.4);
            }

            70% {
                box-shadow:
                    0 0 0 10px rgba(239,68,68,0);
            }

            100% {
                box-shadow:
                    0 0 0 0 rgba(239,68,68,0);
            }
        }

        .critical {

            animation: pulse 2s infinite;
        }

        /* ================================================= */
        /* RESPONSIVE */
        /* ================================================= */

        @media(max-width: 768px) {

            body {
                padding: 15px;
            }

            h1 {
                font-size: 26px;
            }

            .stat-number {
                font-size: 32px;
            }
        }

    </style>

</head>

<body>

    <!-- ================================================= -->
    <!-- TOPBAR -->
    <!-- ================================================= -->

    <div class="topbar">

        <span>AI SOC MONITOR</span>

        <span>STATUS: ACTIVE</span>

    </div>

    <!-- ================================================= -->
    <!-- TITLE -->
    <!-- ================================================= -->

    <h1>
        AI-Powered SOC Threat Detection Dashboard
    </h1>

    <!-- ================================================= -->
    <!-- SUMMARY -->
    <!-- ================================================= -->

    <div class="container">

        <div class="card">

            <h2>Total Events</h2>

            <div class="stat-number"
                 id="total_events">0</div>

        </div>

        <div class="card">

            <h2>Failed Logins</h2>

            <div class="stat-number"
                 id="failed_events">0</div>

        </div>

        <div class="card">

            <h2>Successful Logins</h2>

            <div class="stat-number"
                 id="successful_events">0</div>

        </div>

    </div>

    <!-- ================================================= -->
    <!-- TOP IPS -->
    <!-- ================================================= -->

    <div class="card">

        <h2>Top Attacker IPs</h2>

        <div id="top_ips"></div>

    </div>

    <br>

    <!-- ================================================= -->
    <!-- LIVE FEED -->
    <!-- ================================================= -->

    <div class="card">

        <h2>Live Threat Feed</h2>

        <div id="live_feed"></div>

    </div>

    <br>

    <!-- ================================================= -->
    <!-- EVENTS TABLE -->
    <!-- ================================================= -->

    <div class="card">

        <h2>Recent Security Events</h2>

        <table>

            <thead>

                <tr>

                    <th>ID</th>

                    <th>Timestamp</th>

                    <th>IP Address</th>

                    <th>Username</th>

                    <th>Event Type</th>

                </tr>

            </thead>

            <tbody id="events_table">

            </tbody>

        </table>

    </div>

    <!-- ================================================= -->
    <!-- JAVASCRIPT -->
    <!-- ================================================= -->

    <script>

        async function loadDashboard() {

            // ============================================
            // FETCH SUMMARY
            // ============================================

            const summaryResponse =
                await fetch('/api/summary');

            const summary =
                await summaryResponse.json();

            // ============================================
            // UPDATE STATS
            // ============================================

            document.getElementById(
                'total_events'
            ).innerText =
                summary.total_events;

            document.getElementById(
                'failed_events'
            ).innerText =
                summary.failed_events;

            document.getElementById(
                'successful_events'
            ).innerText =
                summary.successful_events;

            // ============================================
            // TOP ATTACKER IPS
            // ============================================

            const topIpsDiv =
                document.getElementById(
                    'top_ips'
                );

            topIpsDiv.innerHTML = "";

            summary.top_ips.forEach(ip => {

                topIpsDiv.innerHTML += `

                    <div class="threat-card critical">

                        <h3>${ip.ip}</h3>

                        <br>

                        <p>
                            Attack Attempts:
                            ${ip.count}
                        </p>

                    </div>
                `;
            });

            // ============================================
            // FETCH EVENTS
            // ============================================

            const eventsResponse =
                await fetch('/api/events');

            const events =
                await eventsResponse.json();

            // ============================================
            // EVENTS TABLE
            // ============================================

            const table =
                document.getElementById(
                    'events_table'
                );

            table.innerHTML = "";

            events.forEach(event => {

                let row = `

                    <tr>

                        <td>${event.id}</td>

                        <td>${event.timestamp}</td>

                        <td>${event.ip}</td>

                        <td>${event.username}</td>

                        <td class="${event.event_type}">
                            ${event.event_type}
                        </td>

                    </tr>
                `;

                table.innerHTML += row;
            });

            // ============================================
            // LIVE FEED
            // ============================================

            const liveFeed =
                document.getElementById(
                    'live_feed'
                );

            liveFeed.innerHTML = "";

            events.slice(0, 10).forEach(event => {

                const cardClass =
                    event.event_type === "failed"
                    ? "critical"
                    : "success";

                liveFeed.innerHTML += `

                    <div class="threat-card ${cardClass}">

                        <b>
                            ${event.event_type.toUpperCase()}
                        </b>

                        <br><br>

                        IP: ${event.ip}

                        <br>

                        USER: ${event.username}

                        <br>

                        TIME: ${event.timestamp}

                    </div>
                `;
            });
        }

        // ============================================
        // INITIAL LOAD
        // ============================================

        loadDashboard();

        // ============================================
        // AUTO REFRESH
        // ============================================

        setInterval(loadDashboard, 5000);

    </script>

</body>

</html>
"""

    return render_template_string(html)


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print("[+] Starting AI SOC Dashboard")

    print("[+] Dashboard URL : http://localhost:5000")

    print("[+] Monitoring Threat Feed...")

    print("=" * 60)

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
