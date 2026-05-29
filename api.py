"""
Dashboard API backend - serves honeypot stats, logs, and manages services.
Run: python api.py (default http://localhost:5050)
"""
import os
import sqlite3
import logging
import json
from functools import wraps
from datetime import datetime, timezone
from flask import Flask, jsonify, send_from_directory, request, Response

from env_loader import load_env_file

load_env_file()

from honeypot import Logger, HoneypotDatabase, SSHService, FTPService, HTTPService, TelnetService, NCService
from app_meta import APP_NAME, APP_TAGLINE, APP_VERSION
from notifications import provider_status, send_alert, severity_for_category
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
    expected_user = os.environ.get("DASHBOARD_USER")
    expected_pass = os.environ.get("DASHBOARD_PASS")
    if not expected_user or not expected_pass:
        return False
    return username == expected_user and password == expected_pass

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
    remote_addr = request.remote_addr or "unknown"
    trusted_proxies = {
        ip.strip()
        for ip in os.environ.get("HONEYPOT_TRUSTED_PROXIES", "").split(",")
        if ip.strip()
    }
    xff = request.headers.get("X-Forwarded-For", "")
    if xff and remote_addr in trusted_proxies:
        return xff.split(",")[0].strip()
    return remote_addr


def parse_limit(value, default=100, minimum=1, maximum=500):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(minimum, min(parsed, maximum))


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
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://unpkg.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://*.basemaps.cartocdn.com; "
        "connect-src 'self' https://*.basemaps.cartocdn.com; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp


def bootstrap_admin():
    env_user_set = "HONEYPOT_ADMIN_USER" in os.environ
    env_pass_set = "HONEYPOT_ADMIN_PASS" in os.environ
    username = os.environ.get("HONEYPOT_ADMIN_USER", "admin")
    password = os.environ.get("HONEYPOT_ADMIN_PASS", "admin")
    conn = get_db()
    row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
            (username, hash_password(password), utc_now()),
        )
        conn.commit()
        log.info("Bootstrapped admin account from environment.")
    elif not env_user_set and not env_pass_set and username == "admin":
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password("admin"), row["id"]),
        )
        conn.commit()
        log.info("Refreshed built-in local admin account to default credentials.")
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
@requires_token(role="admin")
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
@requires_token(role="admin")
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
@requires_token(role="admin")
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
@requires_token(role="admin")
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
@requires_token(role="admin")
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
@requires_token(role="admin")
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
@requires_token(role="admin")
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

def _risk_level(score):
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "elevated"
    if score > 0:
        return "guarded"
    return "quiet"


def _deployment_checks():
    auth_secret = os.environ.get("HONEYPOT_AUTH_SECRET", "change-me-in-production")
    admin_pass = os.environ.get("HONEYPOT_ADMIN_PASS", "secret")
    public_bind = os.environ.get("HONEYPOT_BIND_HOST", "127.0.0.1") == "0.0.0.0"
    alert_status = provider_status()
    alert_configured = any(p["configured"] for p in alert_status["providers"].values())
    return [
        {
            "id": "auth_secret",
            "label": "Authentication signing secret",
            "status": "warn" if auth_secret in ("change-me-in-production", "") else "pass",
            "message": "Set HONEYPOT_AUTH_SECRET to a long random value before deployment." if auth_secret in ("change-me-in-production", "") else "Custom token signing secret configured.",
        },
        {
            "id": "admin_password",
            "label": "Admin bootstrap password",
            "status": "warn" if admin_pass in ("secret", "change_this_now", "") else "pass",
            "message": "Replace the default admin password before exposing the dashboard." if admin_pass in ("secret", "change_this_now", "") else "Admin password is not using the known default.",
        },
        {
            "id": "bind_host",
            "label": "Dashboard bind host",
            "status": "warn" if public_bind else "pass",
            "message": "Dashboard is configured for all interfaces; protect it with firewall/VPN/reverse proxy auth." if public_bind else "Dashboard bind host is restricted.",
        },
        {
            "id": "alert_channels",
            "label": "Outbound alert channels",
            "status": "pass" if alert_status["enabled"] and alert_configured else "warn",
            "message": "Slack/Telegram/Discord alerting has at least one configured provider." if alert_status["enabled"] and alert_configured else "Set HONEYPOT_ALERTS_ENABLED=true and configure Slack, Telegram, or Discord secrets for live alert delivery.",
        },
    ]


@app.route("/api/threats/summary")
@requires_token()
def threat_summary():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM connections")
    total_connections = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM commands")
    total_commands = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT ip) FROM connections")
    unique_ips = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM commands WHERE LOWER(COALESCE(attack_category, '')) LIKE '%malware%'")
    malware_events = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM commands WHERE LOWER(COALESCE(attack_category, '')) LIKE '%privilege%'")
    privilege_events = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM commands WHERE LOWER(COALESCE(attack_category, '')) LIKE '%brute%'")
    brute_force_events = cur.fetchone()[0]

    cur.execute(
        """
        SELECT c.ip, COUNT(*) AS events, MAX(c.timestamp) AS last_seen,
               COALESCE(NULLIF(MAX(n.asn), ''), 'Unknown') AS asn,
               COALESCE(NULLIF(MAX(n.asn_org), ''), 'Unknown') AS asn_org,
               MAX(COALESCE(n.reputation_score, 0)) AS reputation_score,
               COALESCE(NULLIF(MAX(n.reputation_level), ''), 'unknown') AS reputation_level
        FROM commands c
        LEFT JOIN connections n ON n.ip = c.ip
        WHERE c.ip IS NOT NULL AND c.ip != ''
        GROUP BY c.ip
        ORDER BY events DESC, reputation_score DESC, last_seen DESC
        LIMIT 8
        """
    )
    top_attackers = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT COALESCE(NULLIF(country, ''), 'Unknown') AS country, COUNT(*) AS connections
        FROM connections
        GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
        ORDER BY connections DESC
        LIMIT 8
        """
    )
    top_countries = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT id, ip, service, command, timestamp, attack_category
        FROM commands
        WHERE LOWER(COALESCE(attack_category, '')) LIKE '%malware%'
           OR LOWER(COALESCE(attack_category, '')) LIKE '%privilege%'
        ORDER BY id DESC
        LIMIT 10
        """
    )
    recent_critical = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT COALESCE(NULLIF(asn, ''), 'Unknown') AS asn,
               COALESCE(NULLIF(asn_org, ''), 'Unknown') AS organization,
               COUNT(*) AS connections,
               MAX(COALESCE(reputation_score, 0)) AS max_reputation_score
        FROM connections
        GROUP BY COALESCE(NULLIF(asn, ''), 'Unknown'), COALESCE(NULLIF(asn_org, ''), 'Unknown')
        ORDER BY connections DESC, max_reputation_score DESC
        LIMIT 8
        """
    )
    top_asns = [dict(r) for r in cur.fetchall()]

    cur.execute(
        """
        SELECT COALESCE(NULLIF(reputation_level, ''), 'unknown') AS level,
               COUNT(*) AS connections,
               AVG(COALESCE(reputation_score, 0)) AS avg_score
        FROM connections
        GROUP BY COALESCE(NULLIF(reputation_level, ''), 'unknown')
        ORDER BY connections DESC
        """
    )
    reputation = [dict(r) for r in cur.fetchall()]

    cur.execute("SELECT COUNT(*) FROM cases WHERE status != 'closed'")
    open_cases = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM cases WHERE status = 'closed'")
    closed_cases = cur.fetchone()[0]

    cur.execute(
        """
        SELECT substr(timestamp, 1, 13) || ':00:00Z' AS bucket, COUNT(*) AS events
        FROM commands
        WHERE timestamp IS NOT NULL AND timestamp != ''
        GROUP BY bucket
        ORDER BY bucket DESC
        LIMIT 12
        """
    )
    timeline = [dict(r) for r in reversed(cur.fetchall())]
    conn.close()

    risk_score = min(100, int(
        (malware_events * 8) +
        (privilege_events * 6) +
        (brute_force_events * 3) +
        (unique_ips * 1.5) +
        min(total_commands, 500) * 0.05
    ))
    checks = _deployment_checks()

    return jsonify({
        "risk_score": risk_score,
        "risk_level": _risk_level(risk_score),
        "totals": {
            "connections": total_connections,
            "commands": total_commands,
            "unique_ips": unique_ips,
            "malware_events": malware_events,
            "privilege_events": privilege_events,
            "brute_force_events": brute_force_events,
        },
        "top_attackers": top_attackers,
        "top_countries": top_countries,
        "top_asns": top_asns,
        "reputation": reputation,
        "cases": {"open": open_cases, "closed": closed_cases},
        "recent_critical": recent_critical,
        "timeline": timeline,
        "deployment": {
            "ready": all(c["status"] == "pass" for c in checks),
            "checks": checks,
        },
    })


def _case_dict(row):
    data = dict(row)
    return data


def _report_window_sql(period):
    if period == "weekly":
        return "datetime('now', '-7 days')", "weekly"
    return "datetime('now', '-1 day')", "daily"


def _build_report(period="daily"):
    since_expr, normalized = _report_window_sql(period)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(f"SELECT COUNT(*) FROM connections WHERE datetime(timestamp) >= {since_expr}")
    connections_count = cur.fetchone()[0]
    cur.execute(f"SELECT COUNT(*) FROM commands WHERE datetime(timestamp) >= {since_expr}")
    commands_count = cur.fetchone()[0]
    cur.execute(
        f"""
        SELECT ip, COUNT(*) AS events, MAX(timestamp) AS last_seen
        FROM commands
        WHERE datetime(timestamp) >= {since_expr} AND ip IS NOT NULL AND ip != ''
        GROUP BY ip
        ORDER BY events DESC, last_seen DESC
        LIMIT 10
        """
    )
    top_attackers = [dict(r) for r in cur.fetchall()]
    cur.execute(
        f"""
        SELECT COALESCE(NULLIF(asn, ''), 'Unknown') AS asn,
               COALESCE(NULLIF(asn_org, ''), 'Unknown') AS organization,
               COUNT(*) AS connections,
               MAX(COALESCE(reputation_score, 0)) AS max_reputation_score
        FROM connections
        WHERE datetime(timestamp) >= {since_expr}
        GROUP BY COALESCE(NULLIF(asn, ''), 'Unknown'), COALESCE(NULLIF(asn_org, ''), 'Unknown')
        ORDER BY connections DESC, max_reputation_score DESC
        LIMIT 10
        """
    )
    top_asns = [dict(r) for r in cur.fetchall()]
    cur.execute(
        f"""
        SELECT attack_category, COUNT(*) AS count
        FROM commands
        WHERE datetime(timestamp) >= {since_expr} AND attack_category IS NOT NULL AND attack_category != ''
        GROUP BY attack_category
        ORDER BY count DESC
        LIMIT 10
        """
    )
    categories = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT COUNT(*) FROM cases WHERE status != 'closed'")
    open_cases = cur.fetchone()[0]
    conn.close()
    return {
        "period": normalized,
        "generated_at": utc_now(),
        "summary": {
            "connections": connections_count,
            "commands": commands_count,
            "open_cases": open_cases,
        },
        "top_attackers": top_attackers,
        "top_asns": top_asns,
        "categories": categories,
    }


@app.route("/api/cases", methods=["GET"])
@requires_token()
def list_cases():
    status = (request.args.get("status") or "").strip().lower()
    limit = parse_limit(request.args.get("limit", 100))
    conn = get_db()
    if status:
        rows = conn.execute(
            """
            SELECT id, title, status, severity, source_ip, assignee, summary, created_at, updated_at, closed_at
            FROM cases WHERE status=? ORDER BY id DESC LIMIT ?
            """,
            (status, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT id, title, status, severity, source_ip, assignee, summary, created_at, updated_at, closed_at
            FROM cases ORDER BY id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    conn.close()
    return jsonify([_case_dict(r) for r in rows])


@app.route("/api/cases", methods=["POST"])
@requires_token(role="admin")
def create_case():
    body = request.get_json(silent=True) or {}
    title = (body.get("title") or "").strip()
    severity = (body.get("severity") or "medium").strip().lower()
    status = (body.get("status") or "open").strip().lower()
    source_ip = (body.get("source_ip") or body.get("ip") or "").strip() or None
    assignee = (body.get("assignee") or "").strip() or None
    summary = (body.get("summary") or "").strip() or None
    if not title:
        return jsonify({"error": "title is required"}), 400
    if severity not in {"low", "medium", "high", "critical"}:
        return jsonify({"error": "severity must be low, medium, high, or critical"}), 400
    if status not in {"open", "investigating", "contained", "closed"}:
        return jsonify({"error": "status must be open, investigating, contained, or closed"}), 400
    now = utc_now()
    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO cases (title, status, severity, source_ip, assignee, summary, created_at, updated_at, closed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (title, status, severity, source_ip, assignee, summary, now, now, now if status == "closed" else None),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM cases WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    log_audit(request.user.get("username", "unknown"), "case.create", target=str(cur.lastrowid), details=title)
    return jsonify(_case_dict(row)), 201


@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@requires_token(role="admin")
def update_case(case_id):
    body = request.get_json(silent=True) or {}
    allowed = {"title", "status", "severity", "source_ip", "assignee", "summary"}
    updates = {k: body[k] for k in allowed if k in body}
    if "status" in updates and str(updates["status"]).lower() not in {"open", "investigating", "contained", "closed"}:
        return jsonify({"error": "invalid status"}), 400
    if "severity" in updates and str(updates["severity"]).lower() not in {"low", "medium", "high", "critical"}:
        return jsonify({"error": "invalid severity"}), 400
    conn = get_db()
    existing = conn.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone()
    if not existing:
        conn.close()
        return jsonify({"error": "case not found"}), 404
    fields = []
    values = []
    for key, value in updates.items():
        fields.append(f"{key}=?")
        values.append(str(value).strip() if value is not None else None)
    fields.append("updated_at=?")
    values.append(utc_now())
    if str(updates.get("status", "")).lower() == "closed":
        fields.append("closed_at=?")
        values.append(utc_now())
    values.append(case_id)
    conn.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id=?", values)
    conn.commit()
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    conn.close()
    log_audit(request.user.get("username", "unknown"), "case.update", target=str(case_id), details=json.dumps(sorted(updates)))
    return jsonify(_case_dict(row))


@app.route("/api/reports/<period>")
@requires_token()
def report(period):
    if period not in {"daily", "weekly"}:
        return jsonify({"error": "period must be daily or weekly"}), 400
    return jsonify(_build_report(period))


@app.route("/api/stats")
@requires_token()
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
@requires_token()
def connections():
    req_limit = parse_limit(request.args.get("limit", 100))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, ip, port, service, timestamp, country, city, region, session_duration_sec, lat, lon,
               isp, asn, asn_org, reputation_score, reputation_level, reputation_flags, enrichment_provider
        FROM connections ORDER BY id DESC LIMIT ?
    """, (req_limit,))
    rows = cur.fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/commands")
@requires_token()
def commands():
    limit = parse_limit(request.args.get("limit", 100))
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
@requires_token()
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

@app.route("/api/alerts/status")
@requires_token()
def alerts_status():
    return jsonify(provider_status())


@app.route("/api/alerts/test", methods=["POST"])
@requires_token(role="admin")
def alerts_test():
    payload = request.get_json(silent=True) or {}
    category = payload.get("attack_category") or "Brute Force"
    event = {
        "event_type": "dashboard_test",
        "ip": client_ip(),
        "service": payload.get("service") or "dashboard",
        "command": payload.get("command") or "operator-triggered dashboard alert connectivity test",
        "timestamp": utc_now(),
        "attack_category": category,
        "severity": payload.get("severity") or severity_for_category(category),
    }
    result = send_alert(event)
    actor = request.user.get("username", "unknown")
    log_audit(actor, "alerts.test", target="notifications", details=str(result))
    status_code = 200 if result.get("sent") else 503
    return jsonify({"success": bool(result.get("sent")), "sent": bool(result.get("sent")), "result": result}), status_code


@app.route("/api/services")
@requires_token()
def get_services():
    status = {}
    for name, svc in services.items():
        status[name] = {"running": svc.running, "port": svc.port}
    return jsonify(status)

@app.route("/api/services/<name>/toggle", methods=["POST"])
@requires_token(role="admin")
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
@requires_token(role="admin")
def audit_logs():
    limit = parse_limit(request.args.get("limit", 100))
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
    bind_host = os.environ.get("HONEYPOT_BIND_HOST", "127.0.0.1")
    dashboard_port = int(os.environ.get("HONEYPOT_DASHBOARD_PORT", "5050"))
    app.run(host=bind_host, port=dashboard_port, debug=False)
