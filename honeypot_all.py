#!/usr/bin/env python3
"""
Single-file honeypot: SSH, Telnet, FTP, HTTP, Redis + optional SSH test client.
  Run server:  python honeypot_all.py  [--ssh-port 2222 --telnet-port 2323 --ftp-port 2121 --http-port 8080 --redis-port 6379]
  Run test:    python honeypot_all.py --test [--host 127.0.0.1 --port 2222 ...]
"""

import argparse
import logging
import os
import signal
import socket
import sys
import threading
import time
import uuid
from pathlib import Path

# Paramiko only needed for SSH (server and test client)
try:
    import paramiko
    _paramiko_ok = True
except ImportError:
    paramiko = None
    _paramiko_ok = False


# =============================================================================
# Logger
# =============================================================================

class HoneypotLogger:
    def __init__(self, log_file="honeypot.log"):
        self.logger = logging.getLogger("HoneypotLogger")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_file)
        formatter = logging.Formatter("%(asctime)s - %(message)s")
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def log_command(self, session_id, ip, service, command):
        self.logger.info(f"[Session: {session_id}] [IP: {ip}] [Service: {service}] Command: {command}")

    def log_connection(self, session_id, ip, service, status):
        self.logger.info(f"[Session: {session_id}] [IP: {ip}] [Service: {service}] Status: {status}")


# =============================================================================
# Session manager
# =============================================================================

class SessionManager:
    def __init__(self):
        self.sessions = {}

    def create_session(self, ip, service_type):
        session_id = str(uuid.uuid4())[:8]
        self.sessions[session_id] = {"ip": ip, "service": service_type, "start_time": time.time(), "commands": []}
        return session_id

    def get_session(self, session_id):
        return self.sessions.get(session_id)

    def end_session(self, session_id):
        if session_id in self.sessions:
            del self.sessions[session_id]


# =============================================================================
# Fake shell (shared by SSH and Telnet)
# =============================================================================

class FakeShell:
    def __init__(self):
        self.cwd = "/home/admin"
        self.username = "admin"
        self.hostname = "ubuntu-server"
        self.filesystem = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
            "/home/admin/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n(FAKE UBUNTU KEY)\n-----END OPENSSH PRIVATE KEY-----\n",
            "/proc/version": "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020\n",
            "/etc/os-release": 'NAME="Ubuntu"\nVERSION="20.04.1 LTS (Focal Fossa)"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 20.04.1 LTS"\nVERSION_ID="20.04"\n',
            "/home/admin/notes.txt": "Server maintenance scheduled for Friday.\nDon't forget to backup the database.\n",
        }
        self.valid_commands = ["ls", "pwd", "whoami", "uname", "cat", "help", "exit", "id"]

    def handle_command(self, command_str):
        command_str = command_str.strip()
        if not command_str:
            return ""
        parts = command_str.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd == "pwd":
            return self.cwd + "\n"
        elif cmd == "whoami":
            return self.username + "\n"
        elif cmd == "id":
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin)\n"
        elif cmd == "uname":
            if "-a" in args:
                return "Linux ubuntu-server 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"
        elif cmd == "ls":
            if self.cwd == "/home/admin":
                files = ["notes.txt", ".ssh"]
            elif self.cwd == "/etc":
                files = ["passwd", "shadow", "hosts", "os-release"]
            elif self.cwd == "/":
                files = ["bin", "boot", "dev", "etc", "home", "lib", "proc", "root", "sys", "tmp", "usr", "var"]
            else:
                files = []
            return "  ".join(files) + "\n"
        elif cmd == "cat":
            if not args:
                return "cat: missing operand\n"
            target_file = args[0]
            abs_path = target_file if target_file.startswith("/") else f"{self.cwd}/{target_file}".replace("//", "/")
            if abs_path in self.filesystem:
                return self.filesystem[abs_path]
            return f"cat: {target_file}: No such file or directory\n"
        elif cmd == "exit":
            return "exit"
        elif cmd == "help":
            return "GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally.\n  ls  pwd  whoami  uname  cat  id  exit\n"
        else:
            return f"{cmd}: command not found\n"


# =============================================================================
# SSH honeypot (paramiko)
# =============================================================================

def _ssh_host_key():
    if paramiko is None:
        raise RuntimeError("paramiko is required for SSH. Install with: pip install paramiko")
    return paramiko.RSAKey.generate(2048)


class FakeSSHServer((paramiko.ServerInterface if _paramiko_ok else object)):
    def __init__(self, ip, session_id, logger):
        self.ip = ip
        self.session_id = session_id
        self.logger = logger
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        self.logger.logger.info(f"SSH: Received channel request {kind} for session {self.session_id}")
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.logger.log_command(self.session_id, self.ip, "SSH", f"LOGIN ATTEMPT: USER={username} PASS={password}")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_shell_request(self, channel):
        self.logger.logger.info(f"SSH: Received shell request for session {self.session_id}")
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


class SSHHoneyPot:
    def __init__(self, host="0.0.0.0", port=2222, logger=None, session_manager=None):
        self.host = host
        self.port = port
        self.logger = logger or HoneypotLogger()
        self.session_manager = session_manager or SessionManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._host_key = _ssh_host_key()

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.logger.logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")
            while True:
                client_sock, addr = self.server_socket.accept()
                self.logger.log_connection("PENDING", addr[0], "SSH", "Connected")
                threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()
        except Exception as e:
            self.logger.logger.error(f"Error starting SSH Honeypot: {e}")

    def _handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "SSH")
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(self._host_key)
            server = FakeSSHServer(ip, session_id, self.logger)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                return
            channel = transport.accept(20)
            if channel is None:
                return
            server.event.wait(30)
            if not server.event.is_set():
                self.logger.logger.warning(f"SSH: Timed out waiting for shell request for session {session_id}")
                channel.close()
                return
            shell = FakeShell()
            channel.send(b"Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n")
            while True:
                prompt = f"{shell.username}@{shell.hostname}:{shell.cwd}$ "
                channel.send(prompt.encode())
                cmd_data = b""
                while True:
                    char = channel.recv(1)
                    if not char:
                        return
                    if char == b"\r":
                        channel.send(b"\r\n")
                        break
                    elif char == b"\x7f":
                        channel.send(b"\b \b")
                        cmd_data = cmd_data[:-1]
                    else:
                        channel.send(char)
                        cmd_data += char
                cmd_str = cmd_data.decode("utf-8", errors="ignore").strip()
                if cmd_str:
                    self.logger.log_command(session_id, ip, "SSH", cmd_str)
                    if cmd_str == "exit":
                        break
                    response = shell.handle_command(cmd_str)
                    channel.send(response.replace("\n", "\r\n").encode())
            channel.close()
        except Exception as e:
            self.logger.logger.error(f"Error in SSH session {session_id}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "SSH", "Disconnected")
            self.session_manager.end_session(session_id)


# =============================================================================
# Telnet honeypot
# =============================================================================

class TelnetHoneyPot:
    def __init__(self, host="0.0.0.0", port=2323, logger=None, session_manager=None):
        self.host = host
        self.port = port
        self.logger = logger or HoneypotLogger()
        self.session_manager = session_manager or SessionManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.logger.logger.info(f"Telnet Honeypot listening on {self.host}:{self.port}")
            while True:
                client_sock, addr = self.server_socket.accept()
                self.logger.log_connection("PENDING", addr[0], "TELNET", "Connected")
                threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()
        except Exception as e:
            self.logger.logger.error(f"Error starting Telnet Honeypot: {e}")

    def _handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "TELNET")
        shell = FakeShell()
        try:
            client_sock.send(b"Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n")
            client_sock.send(b"login: ")
            username = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
            self.logger.log_command(session_id, ip, "TELNET", f"LOGIN ATTEMPT: USER={username}")
            client_sock.send(b"Password: ")
            password = client_sock.recv(1024).decode("utf-8", errors="ignore").strip()
            self.logger.log_command(session_id, ip, "TELNET", f"LOGIN ATTEMPT: PASS={password}")
            client_sock.send(b"\r\nLast login: (fake session)\r\n")
            while True:
                prompt = f"{shell.username}@{shell.hostname}:{shell.cwd}$ "
                client_sock.send(prompt.encode("utf-8"))
                cmd_bytes = client_sock.recv(1024)
                if not cmd_bytes:
                    break
                cmd_str = cmd_bytes.decode("utf-8", errors="ignore").strip()
                if not cmd_str:
                    continue
                self.logger.log_command(session_id, ip, "TELNET", cmd_str)
                if cmd_str == "exit":
                    break
                response = shell.handle_command(cmd_str)
                client_sock.send(response.encode("utf-8"))
        except Exception as e:
            self.logger.logger.error(f"Error handling Telnet client {ip}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "TELNET", "Disconnected")
            client_sock.close()
            self.session_manager.end_session(session_id)


# =============================================================================
# FTP honeypot
# =============================================================================

class FTPHoneyPot:
    """Minimal FTP server: banner, USER/PASS, log all commands."""
    def __init__(self, host="0.0.0.0", port=2121, logger=None, session_manager=None):
        self.host = host
        self.port = port
        self.logger = logger or HoneypotLogger()
        self.session_manager = session_manager or SessionManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.logger.logger.info(f"FTP Honeypot listening on {self.host}:{self.port}")
            while True:
                client_sock, addr = self.server_socket.accept()
                self.logger.log_connection("PENDING", addr[0], "FTP", "Connected")
                threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()
        except Exception as e:
            self.logger.logger.error(f"Error starting FTP Honeypot: {e}")

    def _send(self, sock, code_msg):
        sock.sendall((code_msg + "\r\n").encode("utf-8", errors="replace"))

    def _handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "FTP")
        try:
            self._send(client_sock, "220 Welcome to FTP server (honeypot)")
            logged_in = False
            while True:
                try:
                    data = client_sock.recv(1024).decode("utf-8", errors="ignore").strip().replace("\r\n", "\n")
                    if not data:
                        break
                    for line in data.split("\n"):
                        line = line.strip()
                        if not line:
                            continue
                        self.logger.log_command(session_id, ip, "FTP", line)
                        parts = line.split(None, 1)
                        cmd = (parts[0].upper() if parts else "").strip()
                        arg = (parts[1] if len(parts) > 1 else "").strip()
                        if cmd == "USER":
                            self._send(client_sock, "331 Password required")
                        elif cmd == "PASS":
                            self._send(client_sock, "230 Login successful")
                            logged_in = True
                        elif cmd == "QUIT":
                            self._send(client_sock, "221 Goodbye")
                            return
                        elif cmd in ("SYST", "FEAT", "PWD", "TYPE", "PASV", "PORT"):
                            self._send(client_sock, "200 OK" if cmd != "PWD" else "257 \"/\"")
                        elif cmd == "LIST":
                            self._send(client_sock, "150 Here comes the directory listing")
                            self._send(client_sock, "226 Directory send OK")
                        elif cmd in ("CWD", "CDUP", "RETR", "STOR", "DELE", "MKD", "RMD"):
                            self._send(client_sock, "250 OK" if cmd in ("CWD", "CDUP", "MKD", "RMD") else "226 Transfer complete" if cmd == "STOR" else "550 Failed")
                        else:
                            self._send(client_sock, "502 Command not implemented")
                except (ConnectionResetError, BrokenPipeError):
                    break
        except Exception as e:
            self.logger.logger.error(f"Error handling FTP client {ip}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "FTP", "Disconnected")
            client_sock.close()
            self.session_manager.end_session(session_id)


# =============================================================================
# HTTP honeypot
# =============================================================================

class HTTPHoneyPot:
    """Fake HTTP server: log method, path, User-Agent; return fake page."""
    def __init__(self, host="0.0.0.0", port=8080, logger=None, session_manager=None):
        self.host = host
        self.port = port
        self.logger = logger or HoneypotLogger()
        self.session_manager = session_manager or SessionManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.logger.logger.info(f"HTTP Honeypot listening on {self.host}:{self.port}")
            while True:
                client_sock, addr = self.server_socket.accept()
                self.logger.log_connection("PENDING", addr[0], "HTTP", "Connected")
                threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()
        except Exception as e:
            self.logger.logger.error(f"Error starting HTTP Honeypot: {e}")

    def _handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "HTTP")
        try:
            data = client_sock.recv(8192).decode("utf-8", errors="ignore")
            if not data:
                return
            lines = data.split("\r\n")
            first = lines[0] if lines else ""
            method, path, _ = (first.split(None, 2) + ["", "", ""])[:3]
            user_agent = ""
            for line in lines[1:]:
                if line.lower().startswith("user-agent:"):
                    user_agent = line.split(":", 1)[-1].strip()
                    break
            self.logger.log_command(session_id, ip, "HTTP", f"{method} {path} | User-Agent: {user_agent[:200]}")
            body = b"<html><head><title>Welcome</title></head><body><h1>Welcome</h1><p>Server is under maintenance.</p></body></html>"
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html; charset=utf-8\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            client_sock.sendall(response)
        except Exception as e:
            self.logger.logger.error(f"Error handling HTTP client {ip}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "HTTP", "Disconnected")
            try:
                client_sock.close()
            except Exception:
                pass
            self.session_manager.end_session(session_id)


# =============================================================================
# Redis honeypot
# =============================================================================

class RedisHoneyPot:
    """Fake Redis: respond with +OK and log all commands (RESP protocol)."""
    def __init__(self, host="0.0.0.0", port=6379, logger=None, session_manager=None):
        self.host = host
        self.port = port
        self.logger = logger or HoneypotLogger()
        self.session_manager = session_manager or SessionManager()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.logger.logger.info(f"Redis Honeypot listening on {self.host}:{self.port}")
            while True:
                client_sock, addr = self.server_socket.accept()
                self.logger.log_connection("PENDING", addr[0], "REDIS", "Connected")
                threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()
        except Exception as e:
            self.logger.logger.error(f"Error starting Redis Honeypot: {e}")

    def _reply_ok(self, sock):
        sock.sendall(b"+OK\r\n")

    def _reply_pong(self, sock):
        sock.sendall(b"+PONG\r\n")

    def _reply_bulk(self, sock, s):
        b = s.encode("utf-8", errors="replace")
        sock.sendall(b"$%d\r\n" % len(b) + b + b"\r\n")

    def _handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "REDIS")
        try:
            buf = b""
            while True:
                data = client_sock.recv(4096)
                if not data:
                    break
                buf += data
                while buf:
                    if buf[:1] != b"*":
                        buf = buf[buf.find(b"\n") + 1:]
                        continue
                    end = buf.find(b"\r\n")
                    if end == -1:
                        break
                    try:
                        n = int(buf[1:end])
                    except ValueError:
                        buf = buf[end + 2:]
                        continue
                    rest = buf[end + 2:]
                    args = []
                    for _ in range(n):
                        if not rest.startswith(b"$"):
                            break
                        line_end = rest.find(b"\r\n")
                        if line_end == -1:
                            break
                        try:
                            sz = int(rest[1:line_end])
                        except ValueError:
                            break
                        rest = rest[line_end + 2:]
                        if len(rest) < sz + 2:
                            break
                        args.append(rest[:sz].decode("utf-8", errors="replace"))
                        rest = rest[sz + 2:]
                    else:
                        buf = rest
                        if args:
                            cmd_line = " ".join(args)
                            self.logger.log_command(session_id, ip, "REDIS", cmd_line)
                            cmd = args[0].upper()
                            if cmd == "PING":
                                self._reply_pong(client_sock)
                            elif cmd in ("SET", "CONFIG", "GET", "KEYS", "INFO", "CLIENT", "FLUSHALL", "EVAL"):
                                self._reply_ok(client_sock)
                            else:
                                self._reply_ok(client_sock)
                        continue
                    buf = rest
                    break
        except Exception as e:
            self.logger.logger.error(f"Error handling Redis client {ip}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "REDIS", "Disconnected")
            try:
                client_sock.close()
            except Exception:
                pass
            self.session_manager.end_session(session_id)


# =============================================================================
# Server entry point
# =============================================================================

def run_server(ssh_port=2222, telnet_port=2323, ftp_port=2121, http_port=8080, redis_port=6379, log_file="honeypot.log"):
    if paramiko is None:
        print("SSH requires paramiko. Install with: pip install paramiko", file=sys.stderr)
        sys.exit(1)
    signal.signal(signal.SIGINT, lambda s, f: (print("\nStopping..."), sys.exit(0)))
    print("Starting HoneyPot...")
    logger = HoneypotLogger(log_file=log_file)
    paramiko_logger = logging.getLogger("paramiko")
    paramiko_logger.setLevel(logging.DEBUG)
    if logger.logger.handlers:
        paramiko_logger.addHandler(logger.logger.handlers[0])
    session_manager = SessionManager()
    services = [
        TelnetHoneyPot(port=telnet_port, logger=logger, session_manager=session_manager),
        SSHHoneyPot(port=ssh_port, logger=logger, session_manager=session_manager),
        FTPHoneyPot(port=ftp_port, logger=logger, session_manager=session_manager),
        HTTPHoneyPot(port=http_port, logger=logger, session_manager=session_manager),
        RedisHoneyPot(port=redis_port, logger=logger, session_manager=session_manager),
    ]
    for svc in services:
        threading.Thread(target=svc.start, daemon=True).start()
    logger.logger.info("HoneyPot services started (SSH, Telnet, FTP, HTTP, Redis). Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


# =============================================================================
# Test client (SSH)
# =============================================================================

_TEST_DEFAULTS = {
    "host": os.environ.get("SSH_TEST_HOST", "127.0.0.1"),
    "port": int(os.environ.get("SSH_TEST_PORT", "2222")),
    "user": os.environ.get("SSH_TEST_USER", "admin"),
    "password": os.environ.get("SSH_TEST_PASSWORD", "password"),
    "timeout": int(os.environ.get("SSH_TEST_TIMEOUT", "10")),
    "retries": int(os.environ.get("SSH_TEST_RETRIES", "3")),
    "commands": ["ls", "pwd", "whoami", "id", "exit"],
}


def _load_test_config(path):
    p = Path(path)
    if not p.exists():
        return {}
    try:
        if p.suffix.lower() == ".json":
            import json
            return json.loads(p.read_text())
        data = {}
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip()
        return data
    except Exception:
        return {}


def _test_default(key, config):
    key_lower = key.lower().replace("_", "")
    for k, v in config.items():
        if k.lower().replace("_", "") == key_lower:
            return int(v) if key in ("port", "timeout", "retries") else v
    return _TEST_DEFAULTS.get(key)


def _colorize(text, code, no_color):
    if no_color:
        return text
    codes = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m", "cyan": "\033[36m", "reset": "\033[0m"}
    c, r = codes.get(code, ""), codes["reset"]
    return f"{c}{text}{r}" if c else text


def _recv_with_timeout(shell, timeout, chunk=4096):
    buf = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if shell.recv_ready():
            buf.append(shell.recv(chunk).decode(errors="replace"))
            deadline = time.monotonic() + timeout
        else:
            time.sleep(0.05)
    return "".join(buf)


def run_test(
    host, port, user, password, key_path, timeout, retries, commands,
    verbose, quiet, no_color, dry_run,
):
    if dry_run:
        print(f"Would connect to {user}@{host}:{port} (timeout={timeout}s, retries={retries})")
        print("Commands:", commands)
        return 0
    if paramiko is None:
        print("Test client requires paramiko. Install with: pip install paramiko", file=sys.stderr)
        return 1
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for attempt in range(1, retries + 1):
        try:
            if not quiet:
                print(_colorize(f"Connecting to {host}:{port} (attempt {attempt}/{retries})...", "cyan", no_color))
            kw = dict(hostname=host, port=port, username=user, password=password, timeout=timeout, allow_agent=False, look_for_keys=False)
            if key_path and Path(key_path).exists():
                kw["key_filename"] = key_path
                kw["look_for_keys"] = True
            client.connect(**kw)
            break
        except Exception as e:
            if not quiet:
                print(_colorize(f"  Connection failed: {e}", "red", no_color))
            if attempt == retries:
                return 1
            time.sleep(1)
    exit_code = 0
    try:
        if not quiet:
            print(_colorize("Connected.", "green", no_color))
        shell = client.invoke_shell()
        shell.settimeout(timeout)
        if shell.recv_ready():
            _recv_with_timeout(shell, 2.0)
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd or cmd.startswith("#"):
                continue
            try:
                if verbose and not quiet:
                    print(_colorize(f"  Sending: {cmd}", "cyan", no_color))
                shell.send(cmd + "\n")
                time.sleep(0.3)
                out = _recv_with_timeout(shell, float(timeout))
                if verbose and not quiet:
                    print(out[:500] + ("..." if len(out) > 500 else ""))
            except Exception as e:
                exit_code = 2
                if not quiet:
                    print(_colorize(f"  Error: {e}", "red", no_color))
        if not quiet:
            print(_colorize("Test passed." if exit_code == 0 else "Test had failures.", "green" if exit_code == 0 else "red", no_color))
        client.close()
    except Exception as e:
        if not quiet:
            print(_colorize(f"Test failed: {e}", "red", no_color))
        return 2
    return exit_code


def parse_test_args(argv=None):
    # When invoked as honeypot_all.py --test ..., argv is the remainder after --test
    argv = argv if argv is not None else sys.argv[1:]
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", metavar="PATH")
    pre_args, _ = pre.parse_known_args(argv)
    config = _load_test_config(pre_args.config) if pre_args.config else {}
    p = argparse.ArgumentParser(description="Test SSH honeypot (from same file).")
    p.add_argument("--host", default=_test_default("host", config))
    p.add_argument("--port", type=int, default=_test_default("port", config))
    p.add_argument("--user", default=_test_default("user", config))
    p.add_argument("--password", default=_test_default("password", config))
    p.add_argument("--timeout", type=int, default=_test_default("timeout", config))
    p.add_argument("--retries", type=int, default=_test_default("retries", config))
    p.add_argument("--key", metavar="PATH")
    p.add_argument("--commands", nargs="*")
    p.add_argument("--commands-file", metavar="PATH")
    p.add_argument("--config", metavar="PATH")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    return p.parse_args(argv)


# =============================================================================
# Main: server or test
# =============================================================================

def main():
    pre = argparse.ArgumentParser(description="Single-file honeypot: server or test client.")
    pre.add_argument("--test", action="store_true", help="Run SSH test client instead of server")
    pre.add_argument("--ssh-port", type=int, default=2222, help="SSH port (server mode)")
    pre.add_argument("--telnet-port", type=int, default=2323, help="Telnet port (server mode)")
    pre.add_argument("--ftp-port", type=int, default=2121, help="FTP port (server mode)")
    pre.add_argument("--http-port", type=int, default=8080, help="HTTP port (server mode)")
    pre.add_argument("--redis-port", type=int, default=6379, help="Redis port (server mode)")
    pre.add_argument("--log-file", default="honeypot.log", help="Log file (server mode)")
    pre_args, rest = pre.parse_known_args()

    if pre_args.test:
        args = parse_test_args(rest)
        commands = list(args.commands) if args.commands else list(_TEST_DEFAULTS["commands"])
        if args.commands_file:
            pf = Path(args.commands_file)
            if pf.exists():
                commands = [l.strip() for l in pf.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
        sys.exit(run_test(
            host=args.host, port=args.port, user=args.user, password=args.password,
            key_path=args.key, timeout=args.timeout, retries=args.retries, commands=commands,
            verbose=args.verbose, quiet=args.quiet, no_color=args.no_color, dry_run=args.dry_run,
        ))
    run_server(
        ssh_port=pre_args.ssh_port,
        telnet_port=pre_args.telnet_port,
        ftp_port=pre_args.ftp_port,
        http_port=pre_args.http_port,
        redis_port=pre_args.redis_port,
        log_file=pre_args.log_file,
    )


if __name__ == "__main__":
    main()
