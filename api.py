"""
Dashboard API backend - serves honeypot stats, logs, and manages services.
Run: python api.py (default http://localhost:5050)
"""
import os
import sqlite3
import logging
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, jsonify, send_from_directory, request, Response

from honeypot import Logger, HoneypotDatabase, SSHService, FTPService, HTTPService, TelnetService, NCService
from app_meta import APP_NAME, APP_TAGLINE, APP_VERSION
from security import (
    hash_password,
    verify_password,
    create_token,
    verify_token,
    generate_api_key,
    hash_api_key,
)

LOGIN_WINDOW_SECONDS = 60
LOGIN_MAX_ATTEMPTS = 8
TOKEN_TTL_SECONDS = int(os.environ.get("HONEYPOT_TOKEN_TTL_SECONDS", "28800"))
REQUEST_WINDOW_SECONDS = 60
REQUEST_MAX_PER_WINDOW = int(os.environ.get("HONEYPOT_RATE_LIMIT_PER_MIN", "240"))
_login_attempts = {}
_request_attempts = {}

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


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"


def client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limited(ip):
    now = datetime.now(timezone.utc).timestamp()
    attempts = _login_attempts.get(ip, [])
    attempts = [ts for ts in attempts if now - ts <= LOGIN_WINDOW_SECONDS]
    _login_attempts[ip] = attempts
    return len(attempts) >= LOGIN_MAX_ATTEMPTS


def mark_login_attempt(ip):
    now = datetime.now(timezone.utc).timestamp()
    attempts = _login_attempts.get(ip, [])
    attempts.append(now)
    _login_attempts[ip] = attempts


def request_rate_limited(ip):
    now = datetime.now(timezone.utc).timestamp()
    attempts = _request_attempts.get(ip, [])
    attempts = [ts for ts in attempts if now - ts <= REQUEST_WINDOW_SECONDS]
    _request_attempts[ip] = attempts
    return len(attempts) >= REQUEST_MAX_PER_WINDOW


def mark_request(ip):
    now = datetime.now(timezone.utc).timestamp()
    attempts = _request_attempts.get(ip, [])
    attempts.append(now)
    _request_attempts[ip] = attempts


def log_audit(actor, action, target=None, details=None):
    conn = get_db()
    conn.execute(
        """
        INSERT INTO audit_logs (actor, action, target, ip, timestamp, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (actor, action, target, client_ip(), utc_now(), details),
    )
    conn.commit()
    conn.close()


def get_bearer_token():
    authz = request.headers.get("Authorization", "")
    if authz.startswith("Bearer "):
        return authz[7:].strip()
    return None


def get_api_key_token():
    header_key = request.headers.get("X-API-Key", "").strip()
    if header_key:
        return header_key
    authz = request.headers.get("Authorization", "")
    if authz.startswith("ApiKey "):
        return authz[7:].strip()
    return None


def validate_api_key(role=None):
    raw_key = get_api_key_token()
    if not raw_key:
        return None
    key_hash = hash_api_key(raw_key)
    conn = get_db()
    row = conn.execute(
        """
        SELECT id, name, role, is_active
        FROM api_keys
        WHERE key_hash=?
        """,
        (key_hash,),
    ).fetchone()
    if not row or int(row["is_active"]) != 1:
        conn.close()
        return None
    if role and row["role"] != role:
        conn.close()
        return False
    conn.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (utc_now(), row["id"]))
    conn.commit()
    conn.close()
    return {"username": f"api_key:{row['name']}", "role": row["role"], "auth_type": "api_key"}


def requires_token(role=None, allow_basic_fallback=False):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            api_identity = validate_api_key(role=role)
            if api_identity is False:
                return jsonify({"error": "Forbidden"}), 403
            if api_identity:
                request.user = api_identity
                return f(*args, **kwargs)

            token = get_bearer_token()
            if token:
                payload = verify_token(token, TOKEN_TTL_SECONDS)
                if not payload:
                    return jsonify({"error": "Invalid or expired token"}), 401
                if role and payload.get("role") != role:
                    return jsonify({"error": "Forbidden"}), 403
                request.user = payload
                return f(*args, **kwargs)

            if allow_basic_fallback:
                auth = request.authorization
                if auth and check_auth(auth.username, auth.password):
                    request.user = {"username": auth.username, "role": "admin"}
                    return f(*args, **kwargs)

            return jsonify({"error": "Authentication required"}), 401
        return wrapped
    return decorator

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


@app.before_request
def apply_request_rate_limit():
    # Keep auth and static pathing usable while still throttling brute force attacks.
    exempt_prefixes = ("/static",)
    if request.path.startswith(exempt_prefixes):
        return None
    ip = client_ip()
    if request_rate_limited(ip):
        return jsonify({"error": "Rate limit exceeded"}), 429
    mark_request(ip)
    return None


@app.after_request
def apply_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def bootstrap_admin():
    username = os.environ.get("HONEYPOT_ADMIN_USER", "admin")
    password = os.environ.get("HONEYPOT_ADMIN_PASS", "secret")
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
            (username, hash_password(password), utc_now()),
        )
        conn.commit()
        log.info("Bootstrapped admin account from environment.")
    conn.close()

@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")

@app.route("/api/meta")
def meta():
    return jsonify({
        "name": APP_NAME,
        "tagline": APP_TAGLINE,
        "version": APP_VERSION,
        "auth": ["Bearer", "ApiKey", "Basic (legacy for admin endpoints)"],
    })


@app.route("/api/health")
def health():
    conn = get_db()
    conn.execute("SELECT 1")
    conn.close()
    return jsonify({"status": "ok", "service": APP_NAME, "version": APP_VERSION})


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    ip = client_ip()
    if rate_limited(ip):
        return jsonify({"error": "Too many login attempts. Try again shortly."}), 429

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400

    conn = get_db()
    user = conn.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username=?",
        (username,),
    ).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        conn.close()
        mark_login_attempt(ip)
        return jsonify({"error": "Invalid credentials"}), 401

    conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (utc_now(), user["id"]))
    conn.commit()
    conn.close()
    token = create_token({"username": user["username"], "role": user["role"]})
    log_audit(user["username"], "auth.login", details="User authenticated successfully")
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in_seconds": TOKEN_TTL_SECONDS,
        "user": {"username": user["username"], "role": user["role"]},
    })


@app.route("/api/auth/bootstrap", methods=["POST"])
def auth_bootstrap():
    conn = get_db()
    any_user = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
    if any_user:
        conn.close()
        return jsonify({"error": "Bootstrap disabled after first user is created"}), 409

    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    if len(username) < 3 or len(password) < 8:
        conn.close()
        return jsonify({"error": "username >= 3 chars and password >= 8 chars required"}), 400

    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
        (username, hash_password(password), utc_now()),
    )
    conn.commit()
    conn.close()
    log_audit(username, "auth.bootstrap", details="Initial admin account created")
    return jsonify({"success": True, "message": "Bootstrap admin created"})


@app.route("/api/auth/me")
@requires_token()
def auth_me():
    return jsonify({"user": {"username": request.user["username"], "role": request.user["role"]}})


@app.route("/api/users", methods=["GET"])
@requires_token(role="admin", allow_basic_fallback=True)
def list_users():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, username, role, created_at, last_login_at
        FROM users
        ORDER BY id ASC
        """
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/users", methods=["POST"])
@requires_token(role="admin", allow_basic_fallback=True)
def create_user():
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = (body.get("role") or "viewer").strip().lower()
    if role not in ("admin", "viewer"):
        return jsonify({"error": "role must be admin or viewer"}), 400
    if len(username) < 3 or len(password) < 8:
        return jsonify({"error": "username >= 3 chars and password >= 8 chars required"}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        return jsonify({"error": "username already exists"}), 409
    conn.execute(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (username, hash_password(password), role, utc_now()),
    )
    conn.commit()
    conn.close()
    actor = request.user.get("username", "unknown")
    log_audit(actor, "user.create", target=username, details=f"role={role}")
    return jsonify({"success": True, "username": username, "role": role})


@app.route("/api/users/<username>/password", methods=["POST"])
@requires_token(role="admin", allow_basic_fallback=True)
def rotate_user_password(username):
    body = request.get_json(silent=True) or {}
    new_password = body.get("password") or ""
    if len(new_password) < 8:
        return jsonify({"error": "password >= 8 chars required"}), 400
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "user not found"}), 404
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_password), row["id"]))
    conn.commit()
    conn.close()
    actor = request.user.get("username", "unknown")
    log_audit(actor, "user.password.rotate", target=username)
    return jsonify({"success": True, "username": username})


@app.route("/api/users/<username>", methods=["DELETE"])
@requires_token(role="admin", allow_basic_fallback=True)
def delete_user(username):
    actor = request.user.get("username", "unknown")
    if actor == username:
        return jsonify({"error": "cannot delete your own active account"}), 400
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "user not found"}), 404
    conn.execute("DELETE FROM users WHERE id=?", (row["id"],))
    conn.commit()
    conn.close()
    log_audit(actor, "user.delete", target=username)
    return jsonify({"success": True, "username": username})


@app.route("/api/keys", methods=["GET"])
@requires_token(role="admin", allow_basic_fallback=True)
def list_api_keys():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, name, role, created_by, created_at, last_used_at, is_active
        FROM api_keys
        ORDER BY id ASC
        """
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/keys", methods=["POST"])
@requires_token(role="admin", allow_basic_fallback=True)
def create_api_key():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    role = (body.get("role") or "viewer").strip().lower()
    if not name:
        return jsonify({"error": "name is required"}), 400
    if role not in ("admin", "viewer"):
        return jsonify({"error": "role must be admin or viewer"}), 400

    raw_key = generate_api_key()
    conn = get_db()
    conn.execute(
        """
        INSERT INTO api_keys (name, key_hash, role, created_by, created_at, is_active)
        VALUES (?, ?, ?, ?, ?, 1)
        """,
        (name, hash_api_key(raw_key), role, request.user.get("username", "unknown"), utc_now()),
    )
    conn.commit()
    conn.close()
    log_audit(request.user.get("username", "unknown"), "apikey.create", target=name, details=f"role={role}")
    return jsonify({"success": True, "name": name, "role": role, "api_key": raw_key})


@app.route("/api/keys/<int:key_id>/revoke", methods=["POST"])
@requires_token(role="admin", allow_basic_fallback=True)
def revoke_api_key(key_id):
    conn = get_db()
    row = conn.execute("SELECT id, name FROM api_keys WHERE id=?", (key_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "api key not found"}), 404
    conn.execute("UPDATE api_keys SET is_active=0 WHERE id=?", (key_id,))
    conn.commit()
    conn.close()
    log_audit(request.user.get("username", "unknown"), "apikey.revoke", target=row["name"])
    return jsonify({"success": True, "id": key_id, "name": row["name"]})

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
@requires_token(role="admin", allow_basic_fallback=True)
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
    actor = request.user.get("username", "unknown")
    action = "service.stop" if not svc.running else "service.start"
    log_audit(actor, action, target=name, details=f"Service {name} running={svc.running}")
    return jsonify({"success": True, "running": svc.running, "service": name})


@app.route("/api/audit", methods=["GET"])
@requires_token(role="admin", allow_basic_fallback=True)
def audit_logs():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
    except ValueError:
        limit = 100
    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, actor, action, target, ip, timestamp, details
        FROM audit_logs
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

def start_services():
    for name, svc in services.items():
        if not svc.running:
            svc.start()

if __name__ == "__main__":
    bootstrap_admin()
    start_services()
    app.run(host="0.0.0.0", port=5050, debug=False)
