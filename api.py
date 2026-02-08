"""
Dashboard API backend - serves honeypot stats and logs.
Run: python api.py (default http://localhost:5000)
"""
import os
import sqlite3
from collections import Counter
from flask import Flask, jsonify, send_from_directory, request

app = Flask(__name__, static_folder="dashboard", static_url_path="")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "honeypot.db")

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
    req_limit = min(int(request.args.get("limit", 100)), 500)
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ip, port, service, timestamp, country, city, session_duration_sec
        FROM connections ORDER BY id DESC LIMIT ?
    """, (req_limit,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/commands")
def commands():
    limit = min(int(request.args.get("limit", 100)), 500)
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

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
