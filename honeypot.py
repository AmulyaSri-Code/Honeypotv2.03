"""
Multi-service honeypot: SSH, FTP, HTTP, Telnet, NC - all in one file.
Database: honeypot.db | Log: honeypot.log | Connections held 2+ min for IP/geo tracking.
"""
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import random
import signal
import socket
import sqlite3
import sys
import threading
import time
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from ipaddress import ip_address

from env_loader import load_env_file

load_env_file()

from app_meta import APP_NAME, APP_VERSION
from notifications import send_alert_async, severity_for_category
from v31_core import (
    EventWriteBuffer,
    LazyClassifier,
    SessionReplay,
    deception_headers,
    detect_collaborator_payload,
    fingerprint_http_request,
)
from enrichment import enrich_ip

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from ml.attack_classifier import predict as predict_attack
except ImportError:
    def predict_attack(cmd): return None

MIN_SESSION_SECONDS = 120
MAX_CAPTURE_CHARS = int(os.environ.get("HONEYPOT_MAX_CAPTURE_CHARS", "2048"))
SOCKET_TIMEOUT_SECONDS = int(os.environ.get("HONEYPOT_SOCKET_TIMEOUT_SECONDS", "60"))


def sanitize_event_text(value, max_chars=MAX_CAPTURE_CHARS):
    """Normalize attacker-controlled text before DB/log storage.

    Keeps payloads useful for defensive analysis while preventing multiline log
    forging, terminal control characters, and unbounded disk growth.
    """
    text = "" if value is None else str(value)
    normalized = []
    for ch in text:
        if ch == "\n":
            normalized.append("\\n")
        elif ch == "\r":
            normalized.append("\\r")
        elif ch == "\t":
            normalized.append("\\t")
        elif ord(ch) < 32 or ord(ch) == 127:
            normalized.append("?")
        else:
            normalized.append(ch)
    cleaned = "".join(normalized)
    suffix = "...[truncated]"
    if len(cleaned) > max_chars:
        return cleaned[: max(0, max_chars - len(suffix))] + suffix
    return cleaned

# --- Database ---
class HoneypotDatabase:
    def __init__(self, db_path="honeypot.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._write_lock = threading.RLock()
        self._init_db()
        self.command_buffer = EventWriteBuffer(
            flush_interval=float(os.environ.get("HONEYPOT_DB_FLUSH_INTERVAL", "0.5")),
            sink=self._write_command_batch,
        )
        if os.environ.get("HONEYPOT_DB_BUFFER_AUTOSTART", "true").strip().lower() in {"1", "true", "yes", "on"}:
            self.command_buffer.start()

    def _get_conn(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA busy_timeout=30000;")
        return self._local.conn

    def _execute_with_retry(self, operation, attempts=5):
        last_error = None
        for attempt in range(attempts):
            try:
                with self._write_lock:
                    return operation()
            except sqlite3.OperationalError as exc:
                last_error = exc
                if "locked" not in str(exc).lower() or attempt == attempts - 1:
                    raise
                time.sleep(0.05 * (2 ** attempt))
        raise last_error

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, service TEXT,
                timestamp TEXT, country TEXT, city TEXT, region TEXT, lat REAL, lon REAL,
                isp TEXT, raw_geo TEXT, session_duration_sec INTEGER DEFAULT 0,
                asn TEXT, asn_org TEXT, reputation_score INTEGER DEFAULT 0,
                reputation_level TEXT, reputation_flags TEXT, enrichment_provider TEXT
            );
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT, connection_id INTEGER, ip TEXT,
                service TEXT, command TEXT, timestamp TEXT, attack_category TEXT
            );
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'admin',
                created_at TEXT NOT NULL,
                last_login_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT,
                ip TEXT,
                timestamp TEXT NOT NULL,
                details TEXT
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL DEFAULT 'viewer',
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                severity TEXT NOT NULL DEFAULT 'medium',
                source_ip TEXT,
                assignee TEXT,
                summary TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS session_replay_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id INTEGER NOT NULL,
                offset_sec REAL NOT NULL,
                stream TEXT NOT NULL DEFAULT 'o',
                data TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(ip);
            CREATE INDEX IF NOT EXISTS idx_commands_ip ON commands(ip);
            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_cases_source_ip ON cases(source_ip);
            CREATE INDEX IF NOT EXISTS idx_replay_connection ON session_replay_events(connection_id);
        """)
        migrations = [
            ("commands", "attack_category", "TEXT"),
            ("connections", "asn", "TEXT"),
            ("connections", "asn_org", "TEXT"),
            ("connections", "reputation_score", "INTEGER DEFAULT 0"),
            ("connections", "reputation_level", "TEXT"),
            ("connections", "reputation_flags", "TEXT"),
            ("connections", "enrichment_provider", "TEXT"),
        ]
        for table, column, column_type in migrations:
            try:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")
            except sqlite3.OperationalError:
                pass  # Column exists
        conn.commit()
        conn.close()

    def log_connection(self, ip, port, service, country=None, city=None, region=None,
                       lat=None, lon=None, isp=None, raw_geo=None):
        if ip in ("127.0.0.1", "localhost", "::1"):
            import random
            ip = f"{random.randint(11,220)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            loc = random.choice([
                {"c": "United States", "lat": 38.5, "lon": -95.0},
                {"c": "China", "lat": 35.8, "lon": 104.1},
                {"c": "Russia", "lat": 61.5, "lon": 105.3},
                {"c": "Brazil", "lat": -14.2, "lon": -51.9},
                {"c": "Germany", "lat": 51.1, "lon": 10.4},
                {"c": "India", "lat": 20.5, "lon": 78.9}
            ])
            country, city, region, isp = loc["c"], "Demo Node", "Simulated", "Global Botnet"
            lat, lon = loc["lat"] + random.uniform(-4, 4), loc["lon"] + random.uniform(-4, 4)

        enrichment = enrich_ip(ip, cache_db_path=self.db_path)
        country = country or enrichment.get("country")
        city = city or enrichment.get("city")
        region = region or enrichment.get("region")
        lat = lat if lat is not None else enrichment.get("lat")
        lon = lon if lon is not None else enrichment.get("lon")
        isp = isp or enrichment.get("isp")
        raw_geo = raw_geo or enrichment.get("raw_geo")

        def write_connection():
            c = self._get_conn()
            cur = c.cursor()
            cur.execute("""INSERT INTO connections (ip, port, service, timestamp, country, city,
                region, lat, lon, isp, raw_geo, asn, asn_org, reputation_score, reputation_level, reputation_flags, enrichment_provider)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    ip, port, service, datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z",
                    country, city, region, lat, lon, isp, raw_geo, enrichment.get("asn"),
                    enrichment.get("asn_org"), int(enrichment.get("reputation_score") or 0),
                    enrichment.get("reputation_level"), json.dumps(enrichment.get("reputation_flags") or []),
                    enrichment.get("enrichment_provider"),
                ))
            c.commit()
            return cur.lastrowid

        return self._execute_with_retry(write_connection)

    def log_command(self, ip, service, command, connection_id=None, attack_category=None):
        command = sanitize_event_text(command)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"
        self.command_buffer.add({
            "connection_id": connection_id,
            "ip": ip,
            "service": service,
            "command": command,
            "timestamp": timestamp,
            "attack_category": attack_category,
        })
        send_alert_async({
            "event_type": "command",
            "ip": ip,
            "service": service,
            "command": command,
            "timestamp": timestamp,
            "attack_category": attack_category,
            "severity": severity_for_category(attack_category),
        }, logging.getLogger("HoneypotAlerts"))

    def _write_command_batch(self, batch):
        def write_batch():
            c = self._get_conn()
            rows = []
            for event in batch:
                ip = event.get("ip")
                connection_id = event.get("connection_id")
                if connection_id:
                    row = c.execute("SELECT ip FROM connections WHERE id=?", (connection_id,)).fetchone()
                    if row:
                        ip = row[0]
                rows.append((
                    connection_id,
                    ip,
                    event.get("service"),
                    event.get("command"),
                    event.get("timestamp"),
                    event.get("attack_category"),
                ))
            c.executemany(
                "INSERT INTO commands (connection_id, ip, service, command, timestamp, attack_category) VALUES (?,?,?,?,?,?)",
                rows,
            )
            c.commit()
            return len(rows)
        return self._execute_with_retry(write_batch)

    def flush_command_buffer(self):
        return self.command_buffer.flush()

    def update_commands_attack_category(self, connection_id, attack_category):
        self.flush_command_buffer()
        def update_batch():
            c = self._get_conn()
            c.execute(
                "UPDATE commands SET attack_category=? WHERE connection_id=? AND (attack_category IS NULL OR attack_category='')",
                (attack_category, connection_id),
            )
            c.commit()
        return self._execute_with_retry(update_batch)

    def record_session_replay(self, connection_id, offset_sec, data, stream="o"):
        data = sanitize_event_text(data, max_chars=MAX_CAPTURE_CHARS)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"
        def write_replay():
            c = self._get_conn()
            c.execute(
                "INSERT INTO session_replay_events (connection_id, offset_sec, stream, data, timestamp) VALUES (?,?,?,?,?)",
                (connection_id, float(offset_sec or 0), stream or "o", data, timestamp),
            )
            c.commit()
        return self._execute_with_retry(write_replay)

    def render_session_replay(self, connection_id):
        self.flush_command_buffer()
        c = self._get_conn()
        rows = c.execute(
            "SELECT offset_sec, stream, data FROM session_replay_events WHERE connection_id=? ORDER BY offset_sec, id",
            (connection_id,),
        ).fetchall()
        replay = SessionReplay()
        for row in rows:
            replay.record(row["offset_sec"], row["data"], row["stream"])
        return replay.to_asciinema() if rows else None

    def update_session_duration(self, conn_id, duration_sec):
        self.flush_command_buffer()
        def update_duration():
            c = self._get_conn()
            c.execute("UPDATE connections SET session_duration_sec=? WHERE id=?", (duration_sec, conn_id))
            c.commit()
        return self._execute_with_retry(update_duration)

    def close(self):
        if hasattr(self, "command_buffer"):
            self.command_buffer.stop()
        if hasattr(self._local, "conn"):
            self._local.conn.close()
            del self._local.conn

# --- Geolocation ---
def get_geolocation(ip):
    try:
        parsed_ip = ip_address(ip)
        if (
            parsed_ip.is_loopback
            or parsed_ip.is_private
            or parsed_ip.is_link_local
            or parsed_ip.is_multicast
            or parsed_ip.is_reserved
        ):
            return {"country": "Local Network", "city": "Internal", "query": ip}
    except ValueError:
        if ip == "localhost":
            return {"country": "Local Network", "city": "Internal", "query": ip}

    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return {"country": "Local Network", "city": "Internal", "query": ip}
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,lat,lon,isp,query", timeout=5) as r:
            d = json.loads(r.read().decode())
            return d if d.get("status") == "success" else None
    except Exception:
        return None


def log_sensor_connection(db, ip, port, service):
    """Log a sensor connection through the cached enrichment path only."""
    return db.log_connection(ip, port, service)


def classify_session_after_disconnect(db, connection_id, commands, predict_fn=None):
    """Classify a completed session asynchronously and update uncategorized commands."""
    classifier = LazyClassifier(predict_fn or predict_attack, max_workers=1)

    def classify_and_update():
        try:
            result = classifier._classify(connection_id, list(commands))
            db.update_commands_attack_category(connection_id, result.get("attack_category") or "Unknown")
            return result
        finally:
            classifier.queue.shutdown(wait=False)

    return classifier.queue.submit(classify_and_update)

# --- Fake shell ---
FAKE_LS = "total 48\ndrwxr-xr-x  4 root root  4096 Feb  8 10:23 .\ndrwxr-xr-x  5 root root  4096 Feb  6 14:12 ..\ndrwxr-xr-x  2 root root  4096 Feb  7 09:15 documents\n-rw-r--r--  1 root root  2048 Feb  8 10:20 config.ini\n-rw-r--r--  1 root root  5120 Feb  7 16:45 database.sql\n"
FAKE_USERS, FAKE_HOSTS = ["admin", "root", "web"], ["server01", "prod-web-02"]

def get_shell_response(cmd_str, cwd="/home/admin"):
    cmd = (cmd_str.strip().lower().split() or [""])[0]
    args = cmd_str.strip().split()[1:]
    if cmd == "ls" or cmd_str.strip().startswith("ls "): return FAKE_LS, cwd
    if cmd == "pwd": return f"{cwd}\n", cwd
    if cmd == "cd":
        if not args or args[0] in ("~", ""): return "", "/home/admin"
        elif args[0].strip() == "..":
            parts = cwd.rstrip("/").split("/")[:-1]
            return "", "/".join(parts) if parts else "/"
        elif args[0].strip() == ".": return "", cwd
        else:
            new_dir = args[0].strip("/")
            return "", (f"{cwd}/{new_dir}" if cwd != "/" else f"/{new_dir}")
    if cmd == "who": return f"{random.choice(FAKE_USERS)}    pts/0    {random.choice(FAKE_HOSTS)}  Feb  8 10:15\n", cwd
    if cmd == "whoami": return random.choice(FAKE_USERS) + "\n", cwd
    if cmd == "id": return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n", cwd
    if cmd == "uname": return "Linux server01 5.15.0-91-generic x86_64 GNU/Linux\n", cwd
    if cmd in ("cat","head","tail"): return "Permission denied\n", cwd
    if cmd in ("exit","quit","logout"): return "", cwd
    return f"{cmd_str.strip()}: command not found\n", cwd

# --- Logger ---
class Logger:
    def __init__(self):
        self._log = logging.getLogger("Honeypot")
        self._log.setLevel(logging.INFO)
        log_path = os.environ.get("HONEYPOT_LOG_PATH", "honeypot.log")
        max_bytes = int(os.environ.get("HONEYPOT_LOG_MAX_BYTES", str(10 * 1024 * 1024)))
        backup_count = int(os.environ.get("HONEYPOT_LOG_BACKUPS", "5"))
        fh = RotatingFileHandler(log_path, maxBytes=max_bytes, backupCount=backup_count)
        fh.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self._log.addHandler(fh)
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self._log.addHandler(ch)
        
        # Silence paramiko internal logs for dropped connections
        logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    def log_conn(self, ip, port, svc, status, detail=""):
        self._log.info(f"[CONN] {svc}({port}) {ip}: {status}" + (f" - {detail}" if detail else ""))

    def log_cmd(self, ip, port, svc, cmd, attack_category=None):
        cmd = sanitize_event_text(cmd)
        msg = f"[CMD] {svc}({port}) {ip}: {cmd}"
        if attack_category:
            msg += f" [ATTACK: {attack_category}]"
        self._log.info(msg)

    def err(self, svc, msg):
        msg_str = str(msg)
        if not msg_str or "Connection reset by peer" in msg_str or "Broken pipe" in msg_str:
            return
        self._log.error(f"[ERR] {svc}: {msg_str}")

    def info(self, msg):
        self._log.info(msg)

# --- Base service ---
class Service(ABC):
    def __init__(self, name, port, logger, db):
        self.name, self.port, self.logger, self.db = name, port, logger, db
        self.running, self.thread, self.sock = False, None, None
        self.max_connections = int(os.environ.get("HONEYPOT_MAX_CONNECTIONS_PER_SERVICE", "100"))
        self.max_connections_per_ip = int(os.environ.get("HONEYPOT_MAX_CONNECTIONS_PER_IP", "10"))
        self._connection_lock = threading.Lock()
        self._active_connections = 0
        self._active_by_ip = {}

    def _try_acquire_connection(self, addr):
        ip = addr[0] if addr else "unknown"
        with self._connection_lock:
            if self._active_connections >= self.max_connections:
                return False
            if self._active_by_ip.get(ip, 0) >= self.max_connections_per_ip:
                return False
            self._active_connections += 1
            self._active_by_ip[ip] = self._active_by_ip.get(ip, 0) + 1
            return True

    def _release_connection(self, addr):
        ip = addr[0] if addr else "unknown"
        with self._connection_lock:
            self._active_connections = max(0, self._active_connections - 1)
            current = self._active_by_ip.get(ip, 0)
            if current <= 1:
                self._active_by_ip.pop(ip, None)
            else:
                self._active_by_ip[ip] = current - 1

    def _spawn_handler(self, handler, sock, addr):
        if not self._try_acquire_connection(addr):
            try:
                sock.send(b"Service temporarily busy.\r\n")
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            if self.logger:
                self.logger.err(self.name, f"connection limit reached for {addr[0] if addr else 'unknown'}")
            return

        def guarded():
            try:
                handler(sock, addr, self.port, self.logger, self.db)
            finally:
                self._release_connection(addr)

        threading.Thread(target=guarded, daemon=True).start()

    @abstractmethod
    def start(self): pass

    @abstractmethod
    def stop(self): pass

# --- SSH ---
if paramiko:
    HOST_KEY = paramiko.RSAKey.generate(2048)

    class FakeSSH(paramiko.ServerInterface):
        def __init__(self, ip, port, logger, db):
            self.ip, self.port, self.logger, self.db, self.conn_id = ip, port, logger, db, None
            self.commands = []

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_none(self, username):
            return paramiko.AUTH_SUCCESSFUL

        def check_auth_password(self, user, pw):
            if not pw:
                return paramiko.AUTH_FAILED
            cmd = f"auth:{user}:{pw}"
            self.commands.append(cmd)
            self.logger.log_cmd(self.ip, self.port, "ssh", cmd)
            self.db.log_command(self.ip, "ssh", cmd, self.conn_id)
            return paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

        def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
            return True
            
        def check_channel_shell_request(self, channel):
            return True

    def _handle_ssh(sock, addr, port, log, db):
        ip = addr[0]
        cid = log_sensor_connection(db, ip, port, "ssh")
        log.log_conn(ip, port, "ssh", "connected", "enrichment cached")
        start = time.time()
        session_commands = []
        srv = None
        try:
            t = paramiko.Transport(sock)
            t.add_server_key(HOST_KEY)
            srv = FakeSSH(ip, port, log, db)
            srv.conn_id = cid
            t.start_server(server=srv)
            ch = t.accept(60)
            if ch:
                ch.settimeout(300)
                ch.send(b"Welcome to Ubuntu 22.04 LTS\r\nadmin@server01:/home/admin$ ")
                cmd_buffer = ""
                cwd = "/home/admin"
                while True:
                    try:
                        d = ch.recv(1024)
                        if not d: break
                        for char in d.decode("utf-8", errors="ignore"):
                            if char in ('\r', '\n'):
                                ch.send(b"\r\n")
                                cmd = cmd_buffer.strip()
                                if cmd:
                                    session_commands.append(cmd)
                                    log.log_cmd(ip, port, "ssh", cmd)
                                    db.log_command(ip, "ssh", cmd, cid)
                                    out, cwd = get_shell_response(cmd, cwd)
                                    if out:
                                        out = out.replace('\n', '\r\n')
                                        ch.send(out.encode())
                                    if cmd in ("exit", "quit", "logout"): break
                                prompt = f"admin@server01:{cwd}$ "
                                ch.send(prompt.encode())
                                cmd_buffer = ""
                            elif char in ('\x08', '\x7f'):
                                if cmd_buffer:
                                    cmd_buffer = cmd_buffer[:-1]
                                    ch.send(b'\x08 \x08')
                            else:
                                cmd_buffer += char
                                ch.send(char.encode())
                    except (socket.timeout, paramiko.ChannelException): break
            t.close()
        except Exception as e: log.err("ssh", str(e))
        finally:
            try: sock.close()
            except: pass
        db.update_session_duration(cid, int(time.time() - start))
        if srv and srv.commands:
            session_commands.extend(srv.commands)
        if session_commands:
            classify_session_after_disconnect(db, cid, session_commands)

    class SSHService(Service):
        def start(self):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.settimeout(300)
            self.sock.bind((os.environ.get("HONEYPOT_SENSOR_BIND_HOST", "127.0.0.1"), self.port))
            self.sock.listen(50)
            self.running = True
            self.thread = threading.Thread(target=self._loop)
            self.thread.daemon = True
            self.thread.start()
            self.logger.info(f"SSH honeypot on port {self.port}")

        def _loop(self):
            while self.running:
                try:
                    s, a = self.sock.accept()
                    s.settimeout(SOCKET_TIMEOUT_SECONDS)
                    self._spawn_handler(_handle_ssh, s, a)
                except socket.timeout: continue
                except Exception as e:
                    if self.running: self.logger.err("ssh", str(e))

        def stop(self): self.running = False; self.sock and self.sock.close()
else:
    class SSHService(Service):
        def start(self): self.logger.err("ssh", "paramiko not installed")
        def stop(self): pass

# --- FTP ---
def _handle_ftp(sock, addr, port, log, db):
    ip = addr[0]
    cid = log_sensor_connection(db, ip, port, "ftp")
    log.log_conn(ip, port, "ftp", "connected", "enrichment cached")
    start = time.time()
    session_commands = []
    def send(m): sock.send((m + "\r\n").encode())
    try:
        sock.settimeout(300)
        send("220 Welcome")
        while True:
            try:
                d = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if not d: break
                c = (d.split(None, 1) or [""])[0].upper()
                session_commands.append(d)
                log.log_cmd(ip, port, "ftp", d)
                db.log_command(ip, "ftp", d, cid)
                if c == "USER": send("331 Password required")
                elif c == "PASS": send("230 Login successful")
                elif c == "PWD": send('257 "/home/admin"')
                elif c in ("LIST","NLST"): send("150 Listing"); send("226 Done")
                elif c == "QUIT": send("221 Goodbye"); break
                else: send("502 Not implemented")
            except (socket.timeout, ConnectionError): break
    except Exception as e: log.err("ftp", str(e))
    finally: sock.close()
    dur = int(time.time() - start)
    db.update_session_duration(cid, dur)
    if session_commands:
        classify_session_after_disconnect(db, cid, session_commands)

class FTPService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind((os.environ.get("HONEYPOT_SENSOR_BIND_HOST", "127.0.0.1"), self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    s.settimeout(SOCKET_TIMEOUT_SECONDS)
                    self._spawn_handler(_handle_ftp, s, a)
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"FTP honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- HTTP ---
def _handle_http(sock, addr, port, log, db):
    ip = addr[0]
    cid = log_sensor_connection(db, ip, port, "http")
    log.log_conn(ip, port, "http", "connected", "enrichment cached")
    start = time.time()
    session_commands = []
    try:
        sock.settimeout(300)
        d = sock.recv(4096).decode("utf-8", errors="ignore")
        if d:
            line = (d.split("\r\n") or d.split("\n") or [""])[0]
            atk = None
            collaborator = detect_collaborator_payload(d)
            if collaborator:
                atk = "Burp Collaborator Trap"
                db.log_command(ip, "http", f"collaborator:{collaborator['domain']}", cid, atk)
            fp = fingerprint_http_request(d)
            captured = f"{line} [fp:{fp['fingerprint']} ua:{fp['user_agent']}]"
            session_commands.append(captured)
            log.log_cmd(ip, port, "http", line, atk)
            db.log_command(ip, "http", captured, cid, atk)
        body = b"<html><body><h1>Welcome</h1></body></html>"
        header_lines = [
            "HTTP/1.1 200 OK",
            "Content-Type: text/html",
            f"Content-Length: {len(body)}",
        ]
        header_lines.extend(f"{name}: {value}" for name, value in deception_headers().items())
        response = ("\r\n".join(header_lines) + "\r\n\r\n").encode() + body
        sock.send(response)
    except Exception as e: log.err("http", str(e))
    finally: sock.close()
    db.update_session_duration(cid, int(time.time() - start))
    if session_commands:
        classify_session_after_disconnect(db, cid, session_commands)

class HTTPService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind((os.environ.get("HONEYPOT_SENSOR_BIND_HOST", "127.0.0.1"), self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    s.settimeout(SOCKET_TIMEOUT_SECONDS)
                    self._spawn_handler(_handle_http, s, a)
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"HTTP honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- Telnet ---
def _strip_telnet(data):
    r, i = [], 0
    while i < len(data):
        if data[i] == 255 and i + 2 < len(data): i += 3; continue
        r.append(chr(data[i]) if 32 <= data[i] < 127 or data[i] in (10, 13) else "")
        i += 1
    return "".join(r).strip()

def _handle_telnet(sock, addr, port, log, db):
    ip = addr[0]
    cid = log_sensor_connection(db, ip, port, "telnet")
    log.log_conn(ip, port, "telnet", "connected", "enrichment cached")
    start = time.time()
    session_commands = []
    def send(m): sock.send((m + "\r\n").encode())
    try:
        sock.settimeout(300)
        send("Welcome to Linux")
        cwd = "/home/admin"
        sock.send(f"admin@server01:{cwd}$ ".encode())
        while True:
            try:
                d = sock.recv(1024)
                if not d: break
                cmd = _strip_telnet(d)
                if cmd:
                    session_commands.append(cmd)
                    log.log_cmd(ip, port, "telnet", cmd)
                    db.log_command(ip, "telnet", cmd, cid)
                    out, cwd = get_shell_response(cmd, cwd)
                    if out: send(out.strip())
                    sock.send(f"admin@server01:{cwd}$ ".encode())
            except (socket.timeout, ConnectionError): break
    except Exception as e: log.err("telnet", str(e))
    finally: sock.close()
    dur = int(time.time() - start)
    db.update_session_duration(cid, dur)
    if session_commands:
        classify_session_after_disconnect(db, cid, session_commands)

class TelnetService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind((os.environ.get("HONEYPOT_SENSOR_BIND_HOST", "127.0.0.1"), self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    s.settimeout(SOCKET_TIMEOUT_SECONDS)
                    self._spawn_handler(_handle_telnet, s, a)
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"Telnet honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- NC ---
def _handle_nc(sock, addr, port, log, db):
    ip = addr[0]
    cid = log_sensor_connection(db, ip, port, "nc")
    log.log_conn(ip, port, "nc", "connected", "enrichment cached")
    start = time.time()
    session_commands = []
    try:
        sock.settimeout(MIN_SESSION_SECONDS + 60)
        sock.send(b"Connected.\r\n")
        while True:
            try:
                d = sock.recv(4096)
                if not d: break
                dec = d.decode("utf-8", errors="replace").strip()
                if dec:
                    session_commands.append(dec)
                    log.log_cmd(ip, port, "nc", dec)
                    db.log_command(ip, "nc", dec, cid)
                    sock.send(b"ok\r\n")
            except (socket.timeout, ConnectionError, BrokenPipeError): break
    except Exception as e: log.err("nc", str(e))
    finally: sock.close()
    db.update_session_duration(cid, int(time.time() - start))
    if session_commands:
        classify_session_after_disconnect(db, cid, session_commands)

class NCService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind((os.environ.get("HONEYPOT_SENSOR_BIND_HOST", "127.0.0.1"), self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    s.settimeout(SOCKET_TIMEOUT_SECONDS)
                    self._spawn_handler(_handle_nc, s, a)
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"NC honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- Main ---
def main():
    import socket
    import threading
    try:
        from api import app, start_services, services, log, hp_db
        db = hp_db
    except ImportError as e:
        print(f"Failed to load API: {e}")
        import sys
        sys.exit(1)

    start_services()
    log.info("Honeypot running. SSH=2222, FTP=2121, HTTP=8080, Telnet=2323, NC=4444")
    log.info("DB: honeypot.db | Log: honeypot.log | ML: real-time attack classification")
    log.info("Run 'python ml/train.py' first to train model. Ctrl+C to stop.")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0)
            s.connect(('10.254.254.254', 1))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = "127.0.0.1"

    print("\n" + "="*50)
    print(f"{APP_NAME} DASHBOARD")
    print("="*50)
    print(f"  Version:        {APP_VERSION}")
    print("  Local Access:   http://localhost:5050")
    print(f"  Network Access: http://{local_ip}:5050")
    print("="*50 + "\n")

    # Run dashboard in background thread so signal handling works normally
    dashboard_bind_host = os.environ.get("HONEYPOT_BIND_HOST", "127.0.0.1")
    dashboard_port = int(os.environ.get("HONEYPOT_DASHBOARD_PORT", "5050"))
    threading.Thread(target=lambda: app.run(host=dashboard_bind_host, port=dashboard_port, debug=False, use_reloader=False), daemon=True).start()

    def stop(*_):
        log.info("Shutting down...")
        for name, s in services.items(): s.stop()
        db.close()
        import sys
        sys.exit(0)

    import signal
    import time
    import sys
    
    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()