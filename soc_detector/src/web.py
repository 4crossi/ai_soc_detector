"""
Flask dashboard for Phase 3.

Provides simple endpoints to view attack counts, top attacker IPs, and recent alerts.
"""
from flask import Flask, jsonify, render_template_string
import os
from .db import DB


def create_app(db_path: str):
    app = Flask(__name__)
    db = DB(db_path)
    db.connect()

    @app.route("/api/summary")
    def summary():
        cur = db.connect().cursor()
        cur.execute("SELECT COUNT(1) as total_attempts FROM attempts")
        total = cur.fetchone()[0]
        cur.execute("SELECT ip, COUNT(1) as cnt FROM attempts GROUP BY ip ORDER BY cnt DESC LIMIT 10")
        top = [{"ip": row[0], "count": row[1]} for row in cur.fetchall()]
        return jsonify({"total_attempts": total, "top_ips": top})

    @app.route("/api/alerts")
    def alerts():
        cur = db.connect().cursor()
        cur.execute("SELECT ip,severity,reason,ts FROM alerts ORDER BY ts DESC LIMIT 50")
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({"ip": r[0], "severity": r[1], "reason": r[2], "ts": r[3]})
        return jsonify(out)

    @app.route("/")
    def index():
        # Minimal HTML page that polls API endpoints
        html = """
        <!doctype html>
        <html><head><title>SOC Dashboard</title></head><body>
        <h1>SOC Dashboard</h1>
        <div id="summary"></div>
        <h2>Recent Alerts</h2>
        <pre id="alerts"></pre>
        <script>
        async function load(){
          let s = await fetch('/api/summary').then(r=>r.json());
          document.getElementById('summary').innerText = JSON.stringify(s,null,2);
          let a = await fetch('/api/alerts').then(r=>r.json());
          document.getElementById('alerts').innerText = JSON.stringify(a,null,2);
        }
        setInterval(load,2000);
        load();
        </script></body></html>
        """
        return render_template_string(html)

    return app

if __name__ == '__main__':
    cfg_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'configs', 'config.json')
    import json
    with open(cfg_path) as f:
        cfg = json.load(f)
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), cfg.get('db_path','data/soc_events.db'))
    app = create_app(db_path)
    app.run(host='0.0.0.0', port=5000, debug=False)
