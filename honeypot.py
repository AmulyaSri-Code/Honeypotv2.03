"""
Multi-service honeypot: SSH, FTP, HTTP, Telnet, NC - all in one file.
Database: honeypot.db | Log: honeypot.log | Connections held 2+ min for IP/geo tracking.
"""
import json
import logging
import random
import signal
import socket
import sqlite3
import sys
import threading
import time
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from ml.attack_classifier import predict as predict_attack
except ImportError:
    def predict_attack(cmd): return None

MIN_SESSION_SECONDS = 120

# --- Database ---
class HoneypotDatabase:
    def __init__(self, db_path="honeypot.db"):
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self):
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS connections (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, port INTEGER, service TEXT,
                timestamp TEXT, country TEXT, city TEXT, region TEXT, lat REAL, lon REAL,
                isp TEXT, raw_geo TEXT, session_duration_sec INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT, connection_id INTEGER, ip TEXT,
                service TEXT, command TEXT, timestamp TEXT, attack_category TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_connections_ip ON connections(ip);
            CREATE INDEX IF NOT EXISTS idx_commands_ip ON commands(ip);
        """)
        try:
            conn.execute("ALTER TABLE commands ADD COLUMN attack_category TEXT")
        except sqlite3.OperationalError:
            pass  # Column exists
        conn.commit()
        conn.close()

    def log_connection(self, ip, port, service, country=None, city=None, region=None,
                       lat=None, lon=None, isp=None, raw_geo=None):
        c = self._get_conn()
        cur = c.cursor()
        cur.execute("""INSERT INTO connections (ip, port, service, timestamp, country, city,
            region, lat, lon, isp, raw_geo) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (ip, port, service, datetime.utcnow().isoformat(), country, city, region, lat, lon, isp, raw_geo))
        c.commit()
        return cur.lastrowid

    def log_command(self, ip, service, command, connection_id=None, attack_category=None):
        c = self._get_conn()
        c.execute(
            "INSERT INTO commands (connection_id, ip, service, command, timestamp, attack_category) VALUES (?,?,?,?,?,?)",
            (connection_id, ip, service, command, datetime.utcnow().isoformat(), attack_category))
        c.commit()

    def update_session_duration(self, conn_id, duration_sec):
        self._get_conn().execute("UPDATE connections SET session_duration_sec=? WHERE id=?", (duration_sec, conn_id))
        self._get_conn().commit()

    def close(self):
        if hasattr(self._local, "conn"):
            self._local.conn.close()
            del self._local.conn

# --- Geolocation ---
def get_geolocation(ip):
    if ip in ("127.0.0.1", "localhost", "::1"):
        return {"country": "Local", "city": "Local", "query": ip}
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip}?fields=status,country,city,regionName,lat,lon,isp,query", timeout=5) as r:
            d = json.loads(r.read().decode())
            return d if d.get("status") == "success" else None
    except Exception:
        return None

# --- Fake shell ---
FAKE_LS = "total 48\ndrwxr-xr-x  4 root root  4096 Feb  8 10:23 .\ndrwxr-xr-x  5 root root  4096 Feb  6 14:12 ..\ndrwxr-xr-x  2 root root  4096 Feb  7 09:15 documents\n-rw-r--r--  1 root root  2048 Feb  8 10:20 config.ini\n-rw-r--r--  1 root root  5120 Feb  7 16:45 database.sql\n"
FAKE_USERS, FAKE_HOSTS = ["admin", "root", "web"], ["server01", "prod-web-02"]

def get_shell_response(cmd_str):
    cmd = (cmd_str.strip().lower().split() or [""])[0]
    if cmd == "ls" or cmd_str.strip().startswith("ls "): return FAKE_LS
    if cmd == "pwd": return "/home/admin\n"
    if cmd == "who": return f"{random.choice(FAKE_USERS)}    pts/0    {random.choice(FAKE_HOSTS)}  Feb  8 10:15\n"
    if cmd == "whoami": return random.choice(FAKE_USERS) + "\n"
    if cmd == "id": return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)\n"
    if cmd == "uname": return "Linux server01 5.15.0-91-generic x86_64 GNU/Linux\n"
    if cmd in ("cat","head","tail"): return "Permission denied\n"
    if cmd in ("exit","quit","logout"): return ""
    return f"{cmd_str.strip()}: command not found\n"

# --- Logger ---
class Logger:
    def __init__(self):
        self._log = logging.getLogger("Honeypot")
        self._log.setLevel(logging.INFO)
        fh = logging.FileHandler("honeypot.log")
        fh.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self._log.addHandler(fh)
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
        self._log.addHandler(ch)

    def log_conn(self, ip, port, svc, status, detail=""):
        self._log.info(f"[CONN] {svc}({port}) {ip}: {status}" + (f" - {detail}" if detail else ""))

    def log_cmd(self, ip, port, svc, cmd, attack_category=None):
        msg = f"[CMD] {svc}({port}) {ip}: {cmd}"
        if attack_category:
            msg += f" [ATTACK: {attack_category}]"
        self._log.info(msg)

    def err(self, svc, msg):
        self._log.error(f"[ERR] {svc}: {msg}")

    def info(self, msg):
        self._log.info(msg)

# --- Base service ---
class Service(ABC):
    def __init__(self, name, port, logger, db):
        self.name, self.port, self.logger, self.db = name, port, logger, db
        self.running, self.thread, self.sock = False, None, None

    @abstractmethod
    def start(self): pass

    @abstractmethod
    def stop(self): pass

# --- SSH ---
if paramiko:
    class FakeSSH(paramiko.ServerInterface):
        def __init__(self, ip, port, logger, db):
            self.ip, self.port, self.logger, self.db, self.conn_id = ip, port, logger, db, None

        def check_auth_password(self, user, pw):
            cmd = f"auth:{user}:{pw}"
            atk = predict_attack(cmd)
            self.logger.log_cmd(self.ip, self.port, "ssh", cmd, atk)
            self.db.log_command(self.ip, "ssh", cmd, self.conn_id, atk)
            return paramiko.AUTH_SUCCESSFUL

        def check_channel_request(self, kind, chanid):
            return paramiko.OPEN_SUCCEEDED

    def _handle_ssh(sock, addr, port, log, db):
        ip = addr[0]
        geo = get_geolocation(ip)
        cid = db.log_connection(ip, port, "ssh", geo.get("country") if geo else None,
            geo.get("city") if geo else None, geo.get("regionName") if geo else None,
            geo.get("lat") if geo else None, geo.get("lon") if geo else None,
            geo.get("isp") if geo else None, str(geo) if geo else None)
        log.log_conn(ip, port, "ssh", "connected", f"{geo.get('country','N/A')}/{geo.get('city','N/A')}" if geo else "")
        start = time.time()
        try:
            t = paramiko.Transport(sock)
            t.set_gss_api(sigma=False)
            t.add_server_key(paramiko.RSAKey.generate(2048))
            srv = FakeSSH(ip, port, log, db)
            srv.conn_id = cid
            t.start_server(server=srv)
            ch = t.accept(60)
            if ch:
                ch.settimeout(300)
                ch.send(b"Welcome to Ubuntu 22.04 LTS\r\n$ ")
                while True:
                    try:
                        d = ch.recv(1024)
                        if not d: break
                        cmd = d.decode("utf-8", errors="ignore").strip()
                        if cmd:
                            atk = predict_attack(cmd)
                            log.log_cmd(ip, port, "ssh", cmd, atk)
                            db.log_command(ip, "ssh", cmd, cid, atk)
                            out = get_shell_response(cmd)
                            if out: ch.send(out.encode())
                            ch.send(b"$ ")
                    except (socket.timeout, paramiko.ChannelException): break
            t.close()
        except Exception as e: log.err("ssh", str(e))
        db.update_session_duration(cid, int(time.time() - start))

    class SSHService(Service):
        def start(self):
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.settimeout(300)
            self.sock.bind(("0.0.0.0", self.port))
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
                    s.settimeout(300)
                    threading.Thread(target=_handle_ssh, args=(s, a, self.port, self.logger, self.db), daemon=True).start()
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
    geo = get_geolocation(ip)
    cid = db.log_connection(ip, port, "ftp", geo.get("country") if geo else None,
        geo.get("city") if geo else None, geo.get("regionName") if geo else None,
        geo.get("lat") if geo else None, geo.get("lon") if geo else None,
        geo.get("isp") if geo else None, str(geo) if geo else None)
    log.log_conn(ip, port, "ftp", "connected", geo.get("country","N/A") if geo else "")
    start = time.time()
    def send(m): sock.send((m + "\r\n").encode())
    try:
        sock.settimeout(300)
        send("220 Welcome")
        while True:
            try:
                d = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if not d: break
                c = (d.split(None, 1) or [""])[0].upper()
                atk = predict_attack(d)
                log.log_cmd(ip, port, "ftp", d, atk)
                db.log_command(ip, "ftp", d, cid, atk)
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
    if dur < MIN_SESSION_SECONDS: time.sleep(MIN_SESSION_SECONDS - dur)

class FTPService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    threading.Thread(target=_handle_ftp, args=(s, a, self.port, self.logger, self.db), daemon=True).start()
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"FTP honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- HTTP ---
def _handle_http(sock, addr, port, log, db):
    ip = addr[0]
    geo = get_geolocation(ip)
    cid = db.log_connection(ip, port, "http", geo.get("country") if geo else None,
        geo.get("city") if geo else None, geo.get("regionName") if geo else None,
        geo.get("lat") if geo else None, geo.get("lon") if geo else None,
        geo.get("isp") if geo else None, str(geo) if geo else None)
    log.log_conn(ip, port, "http", "connected", geo.get("country","N/A") if geo else "")
    start = time.time()
    try:
        sock.settimeout(300)
        d = sock.recv(4096).decode("utf-8", errors="ignore")
        if d:
            line = (d.split("\r\n") or d.split("\n") or [""])[0]
            atk = predict_attack(line)
            log.log_cmd(ip, port, "http", line, atk)
            db.log_command(ip, "http", line, cid, atk)
        body = b"<html><body><h1>Welcome</h1></body></html>"
        sock.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
        if time.time() - start < MIN_SESSION_SECONDS:
            sock.settimeout(MIN_SESSION_SECONDS + 10)
            try: sock.recv(1)
            except socket.timeout: pass
    except Exception as e: log.err("http", str(e))
    finally: sock.close()
    db.update_session_duration(cid, int(time.time() - start))

class HTTPService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    threading.Thread(target=_handle_http, args=(s, a, self.port, self.logger, self.db), daemon=True).start()
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
    geo = get_geolocation(ip)
    cid = db.log_connection(ip, port, "telnet", geo.get("country") if geo else None,
        geo.get("city") if geo else None, geo.get("regionName") if geo else None,
        geo.get("lat") if geo else None, geo.get("lon") if geo else None,
        geo.get("isp") if geo else None, str(geo) if geo else None)
    log.log_conn(ip, port, "telnet", "connected", geo.get("country","N/A") if geo else "")
    start = time.time()
    def send(m): sock.send((m + "\r\n").encode())
    try:
        sock.settimeout(300)
        send("Welcome to Linux")
        send("$ ")
        while True:
            try:
                d = sock.recv(1024)
                if not d: break
                cmd = _strip_telnet(d)
                if cmd:
                    atk = predict_attack(cmd)
                    log.log_cmd(ip, port, "telnet", cmd, atk)
                    db.log_command(ip, "telnet", cmd, cid, atk)
                    out = get_shell_response(cmd)
                    if out: send(out.strip())
                    send("$ ")
            except (socket.timeout, ConnectionError): break
    except Exception as e: log.err("telnet", str(e))
    finally: sock.close()
    dur = int(time.time() - start)
    db.update_session_duration(cid, dur)
    if dur < MIN_SESSION_SECONDS: time.sleep(MIN_SESSION_SECONDS - dur)

class TelnetService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    threading.Thread(target=_handle_telnet, args=(s, a, self.port, self.logger, self.db), daemon=True).start()
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"Telnet honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- NC ---
def _handle_nc(sock, addr, port, log, db):
    ip = addr[0]
    geo = get_geolocation(ip)
    cid = db.log_connection(ip, port, "nc", geo.get("country") if geo else None,
        geo.get("city") if geo else None, geo.get("regionName") if geo else None,
        geo.get("lat") if geo else None, geo.get("lon") if geo else None,
        geo.get("isp") if geo else None, str(geo) if geo else None)
    log.log_conn(ip, port, "nc", "connected", geo.get("country","N/A") if geo else "")
    start = time.time()
    try:
        sock.settimeout(MIN_SESSION_SECONDS + 60)
        sock.send(b"Connected.\r\n")
        while True:
            try:
                d = sock.recv(4096)
                if not d: break
                dec = d.decode("utf-8", errors="replace").strip()
                if dec:
                    atk = predict_attack(dec)
                    log.log_cmd(ip, port, "nc", dec, atk)
                    db.log_command(ip, "nc", dec, cid, atk)
                    sock.send(b"ok\r\n")
            except (socket.timeout, ConnectionError, BrokenPipeError): break
        if time.time() - start < MIN_SESSION_SECONDS:
            time.sleep(MIN_SESSION_SECONDS - (time.time() - start))
    except Exception as e: log.err("nc", str(e))
    finally: sock.close()
    db.update_session_duration(cid, int(time.time() - start))

class NCService(Service):
    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(300)
        self.sock.bind(("0.0.0.0", self.port))
        self.sock.listen(50)
        self.running = True
        def loop():
            while self.running:
                try:
                    s, a = self.sock.accept()
                    threading.Thread(target=_handle_nc, args=(s, a, self.port, self.logger, self.db), daemon=True).start()
                except socket.timeout: continue
        self.thread = threading.Thread(target=loop, daemon=True)
        self.thread.start()
        self.logger.info(f"NC honeypot on port {self.port}")

    def stop(self): self.running = False; self.sock and self.sock.close()

# --- Main ---
def main():
    log = Logger()
    db = HoneypotDatabase()
    svcs = [
        (SSHService("ssh", 2222, log, db), 2222),
        (FTPService("ftp", 2121, log, db), 2121),
        (HTTPService("http", 8080, log, db), 8080),
        (TelnetService("telnet", 2323, log, db), 2323),
        (NCService("nc", 4444, log, db), 4444),
    ]
    for s, p in svcs:
        s.start()
    log.info("Honeypot running. SSH=2222, FTP=2121, HTTP=8080, Telnet=2323, NC=4444")
    log.info("DB: honeypot.db | Log: honeypot.log | ML: real-time attack classification")
    log.info("Run 'python ml/train.py' first to train model. Ctrl+C to stop.")

    def stop(*_):
        log.info("Shutting down...")
        for s, _ in svcs: s.stop()
        db.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, stop)
    while True:
        time.sleep(60)

if __name__ == "__main__":
    main()
