"""
AI-Powered SOC Threat Detection Dashboard
-----------------------------------------

Professional SOC Dashboard using:
- Flask
- SQLite
- Live Threat Feed
- Auto Refresh
- REST APIs

Features:
- Real-time attack monitoring
- Top attacker IPs
- Live security feed
- Recent events table
- Auto-refresh every 5 seconds
- Dark SOC theme

Author: Crossi
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

    # Total events
    cursor.execute("""
        SELECT COUNT(*) as total
        FROM events
    """)

    total_events = cursor.fetchone()["total"]

    # Failed logins
    cursor.execute("""
        SELECT COUNT(*) as failed
        FROM events
        WHERE event_type='failed'
    """)

    failed_events = cursor.fetchone()["failed"]

    # Successful logins
    cursor.execute("""
        SELECT COUNT(*) as success
        FROM events
        WHERE event_type='accepted'
    """)

    success_events = cursor.fetchone()["success"]

    # Top attacker IPs
    cursor.execute("""
        SELECT
            ip,
            COUNT(*) as count
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
# DASHBOARD PAGE
# ============================================================

@app.route("/")
def dashboard():

    html = """

    <!DOCTYPE html>

    <html>

    <head>

        <title>AI SOC Dashboard</title>

        <style>

            body {
                background-color: #0f172a;
                color: white;
                font-family: Arial;
                margin: 0;
                padding: 20px;
            }

            h1 {
                color: #38bdf8;
            }

            h2 {
                color: #38bdf8;
            }

            .container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
            }

            .card {
                background: #1e293b;
                padding: 20px;
                border-radius: 12px;
                box-shadow: 0 0 10px rgba(0,0,0,0.3);
                margin-bottom: 20px;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }

            th, td {
                padding: 12px;
                border: 1px solid #334155;
                text-align: left;
            }

            th {
                background: #0f172a;
            }

            tr:nth-child(even) {
                background: #162033;
            }

            .failed {
                color: #ef4444;
                font-weight: bold;
            }

            .accepted {
                color: #22c55e;
                font-weight: bold;
            }

            .threat-card {
                background: #0f172a;
                padding: 15px;
                margin-top: 10px;
                border-radius: 10px;
            }

            .critical {
                border-left: 5px solid red;
            }

            .success {
                border-left: 5px solid green;
            }

        </style>

    </head>

    <body>

        <h1>AI-Powered SOC Threat Detection Dashboard</h1>

        <!-- ================================================= -->
        <!-- SUMMARY CARDS -->
        <!-- ================================================= -->

        <div class="container">

            <div class="card">

                <h2>Total Events</h2>

                <h1 id="total_events">0</h1>

            </div>

            <div class="card">

                <h2>Failed Logins</h2>

                <h1 id="failed_events">0</h1>

            </div>

            <div class="card">

                <h2>Successful Logins</h2>

                <h1 id="successful_events">0</h1>

            </div>

        </div>

        <!-- ================================================= -->
        <!-- TOP ATTACKERS -->
        <!-- ================================================= -->

        <div class="card">

            <h2>Top Attacker IPs</h2>

            <div id="top_ips"></div>

        </div>

        <!-- ================================================= -->
        <!-- LIVE THREAT FEED -->
        <!-- ================================================= -->

        <div class="card">

            <h2>Live Threat Feed</h2>

            <div id="live_feed"></div>

        </div>

        <!-- ================================================= -->
        <!-- EVENT TABLE -->
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

            // --------------------------------------------
            // LOAD SUMMARY
            // --------------------------------------------

            const summaryResponse =
                await fetch('/api/summary');

            const summary =
                await summaryResponse.json();

            document.getElementById(
                'total_events'
            ).innerText = summary.total_events;

            document.getElementById(
                'failed_events'
            ).innerText = summary.failed_events;

            document.getElementById(
                'successful_events'
            ).innerText = summary.successful_events;

            // --------------------------------------------
            // TOP IPS
            // --------------------------------------------

            const topIpsDiv =
                document.getElementById(
                    'top_ips'
                );

            topIpsDiv.innerHTML = "";

            summary.top_ips.forEach(ip => {

                topIpsDiv.innerHTML += `

                    <div class="threat-card critical">

                        <h3>${ip.ip}</h3>

                        <p>
                            Attack Attempts: ${ip.count}
                        </p>

                    </div>
                `;
            });

            // --------------------------------------------
            // LOAD EVENTS
            // --------------------------------------------

            const eventsResponse =
                await fetch('/api/events');

            const events =
                await eventsResponse.json();

            // --------------------------------------------
            // EVENTS TABLE
            // --------------------------------------------

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

            // --------------------------------------------
            // LIVE THREAT FEED
            // --------------------------------------------

            const liveFeed =
                document.getElementById(
                    'live_feed'
                );

            liveFeed.innerHTML = "";

            events.slice(0, 10).forEach(event => {

                let cardClass =
                    event.event_type == "failed"
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

        // Initial load
        loadDashboard();

        // Auto refresh every 5 seconds
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

    print("[+] Starting SOC Dashboard...")

    print("[+] Dashboard URL: http://localhost:5000")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
