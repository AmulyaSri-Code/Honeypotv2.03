"""
Dashboard API backend - serves honeypot stats, logs, and manages services.
Run: python api.py (default http://localhost:5050)
"""
import os
import sqlite3
import os
from collections import Counter
import logging
from functools import wraps
from flask import Flask, jsonify, send_from_directory, request, Response

from honeypot import Logger, HoneypotDatabase, SSHService, FTPService, HTTPService, TelnetService, NCService

def check_auth(username, password):
    return username == os.environ.get("DASHBOARD_USER", "admin") and password == os.environ.get("DASHBOARD_PASS", "secret")

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return Response('Unauthorized', 401, {'WWW-Authenticate': 'Basic realm="Login Required"'})
        return f(*args, **kwargs)
    return decorated

app = Flask(__name__, static_folder="dashboard", static_url_path="")
# Silence the default Flask/Werkzeug HTTP logs
werkzeug_log = logging.getLogger('werkzeug')
werkzeug_log.setLevel(logging.ERROR)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.db")

# Global honeypot services
log = Logger()
hp_db = HoneypotDatabase(DB_PATH)
services = {
    "ssh": SSHService("ssh", 2222, log, hp_db),
    "ftp": FTPService("ftp", 2121, log, hp_db),
    "http": HTTPService("http", 8080, log, hp_db),
    "telnet": TelnetService("telnet", 2323, log, hp_db),
    "nc": NCService("nc", 4444, log, hp_db),
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")

@app.route("/api/stats")
def stats():
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("SELECT COUNT(*) FROM connections")
    total_conn = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(*) FROM commands")
    total_cmds = cur.fetchone()[0]
    
    cur.execute("SELECT COUNT(DISTINCT ip) FROM connections")
    unique_ips = cur.fetchone()[0]
    
    cur.execute("SELECT service, COUNT(*) FROM connections GROUP BY service")
    by_service = {r[0]: r[1] for r in cur.fetchall()}
    
    cur.execute("SELECT attack_category, COUNT(*) FROM commands WHERE attack_category IS NOT NULL AND attack_category != 'Unknown' GROUP BY attack_category")
    by_attack = {r[0]: r[1] for r in cur.fetchall()}
    
    conn.close()
    return jsonify({
        "total_connections": total_conn,
        "total_commands": total_cmds,
        "unique_ips": unique_ips,
        "by_service": by_service,
        "by_attack": by_attack,
    })

@app.route("/api/connections")
def connections():
    try: req_limit = min(int(request.args.get("limit", 100)), 500)
    except ValueError: req_limit = 100
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ip, port, service, timestamp, country, city, session_duration_sec, lat, lon
        FROM connections ORDER BY id DESC LIMIT ?
    """, (req_limit,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/commands")
def commands():
    try: limit = min(int(request.args.get("limit", 100)), 500)
    except ValueError: limit = 100
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ip, service, command, timestamp, attack_category
        FROM commands ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/attacks")
def attacks():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT attack_category, COUNT(*) as count FROM commands
        WHERE attack_category IS NOT NULL AND attack_category != '' AND attack_category != 'Unknown'
        GROUP BY attack_category ORDER BY count DESC
    """)
    rows = cur.fetchall()
    conn.close()
    return jsonify([{"category": r[0], "count": r[1]} for r in rows])

@app.route("/api/services")
def get_services():
    status = {}
    for name, svc in services.items():
        status[name] = {"running": svc.running, "port": svc.port}
    return jsonify(status)

@app.route("/api/services/<name>/toggle", methods=["POST"])
@requires_auth
def toggle_service(name):
    if name not in services:
        return jsonify({"error": "Service not found"}), 404
    svc = services[name]
    if svc.running:
        svc.stop()
        log.info(f"Service {name} manually stopped via API.")
    else:
        svc.start()
        log.info(f"Service {name} manually started via API.")
    return jsonify({"success": True, "running": svc.running, "service": name})

def start_services():
    for name, svc in services.items():
        if not svc.running:
            svc.start()

if __name__ == "__main__":
    start_services()
    app.run(host="0.0.0.0", port=5050, debug=False)
