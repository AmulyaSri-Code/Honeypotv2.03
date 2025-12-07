import socket
import threading
import logging
import sys
import time
import concurrent.futures
import paramiko
import os
import mysql.connector
from datetime import datetime

# --- Database Configuration ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'honeypot',
    'password': 'honeypot_password',
    'database': 'honeypot_logs'
}

# --- Logging Setup ---
def setup_logger(name='honeypot', log_file='honeypot_single.log', level=logging.INFO):
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    
    handler = logging.FileHandler(log_file)        
    handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    logger.addHandler(console_handler)
    return logger

logger = setup_logger()


# --- Database Logging ---
def log_attack(service, source_ip, payload=None):
    """
    Logs an attack to the MySQL database.
    """
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor()
        
        query = "INSERT INTO logs (timestamp, service, source_ip, payload) VALUES (%s, %s, %s, %s)"
        val = (datetime.now(), service, source_ip, payload)
        
        cursor.execute(query, val)
        cnx.commit()
        
        cursor.close()
        cnx.close()
        logger.info(f"Logged to DB: {service} attack from {source_ip}")
    except Exception as e:
        logger.error(f"Failed to log to DB: {e}")

# --- Fake Shell ---
class FakeShell:
    def __init__(self, client_socket, addr):
        self.client_socket = client_socket
        self.addr = addr
        self.cwd = "/home/user"
        self.hostname = "ubuntu"
        self.username = "user"
        self.files = {
            "/home/user": ["Documents", "Downloads", "notes.txt"],
            "/home/user/Documents": ["secret_plan.pdf", "passwords.txt"],
            "/": ["bin", "boot", "dev", "etc", "home", "lib", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var"]
        }

    def send(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            self.client_socket.send(data)
        except:
            pass

    def start(self):
        try:
            self.send(f"Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n\r\n")
            while True:
                prompt = f"{self.username}@{self.hostname}:{self.cwd}$ "
                self.send(prompt)
                
                command_buffer = ""
                while True:
                    char = self.client_socket.recv(1)
                    if not char:
                        return
                    
                    if char == b'\r' or char == b'\n': # Return
                        self.send(b'\r\n')
                        break
                    elif char == b'\x03': # Ctrl+C
                        self.send(b'^C\r\n')
                        command_buffer = ""
                        break
                    elif char == b'\x7f': # Backspace
                        if len(command_buffer) > 0:
                            command_buffer = command_buffer[:-1]
                            self.send(b'\b \b')
                    else:
                        self.send(char) # Echo
                        command_buffer += char.decode('utf-8', errors='ignore')

                command = command_buffer.strip()
                if not command:
                    continue

                # Log ALL commands
                log_attack("SHELL_CMD", self.addr, command)

                if command == "exit":
                    break
                elif command.startswith("ls"):
                    self.handle_ls()
                elif command == "pwd":
                    self.send(f"{self.cwd}\r\n")
                elif command == "whoami":
                    self.send(f"{self.username}\r\n")
                elif command == "id":
                    self.send(f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username})\r\n")
                elif command == "uname -a" or command == "uname":
                    self.send(f"Linux {self.hostname} 5.4.0-74-generic #83-Ubuntu SMP Sat May 8 02:35:39 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\r\n")
                elif command == "help":
                    self.send("GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)\r\nThese shell commands are defined internally.  Type `help' to see this list.\r\n\r\nls pwd whoami id uname exit help\r\n")
                else:
                    self.send(f"{command}: command not found\r\n")

        except Exception as e:
            logger.error(f"FakeShell error: {e}")

    def handle_ls(self):
        current_files = self.files.get(self.cwd, [])
        output = "  ".join(current_files) + "\r\n"
        self.send(output)

# --- HTTP Honeypot ---
class HTTPHoneypot:
    def __init__(self, host='0.0.0.0', port=8080, max_workers=50):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.server_socket = None
        self.is_running = False
        self.executor = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            logger.info(f"HTTP Honeypot running on {self.host}:{self.port} with {self.max_workers} workers")
            
            while self.is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    self.executor.submit(self.handle_client, client_socket, addr)
                except OSError:
                    break
        except Exception as e:
            logger.error(f"Failed to start HTTP Honeypot: {e}")

    def handle_client(self, client_socket, addr):
        logger.info(f"HTTP Connection from {addr[0]}:{addr[1]}")
        try:
            request = client_socket.recv(1024).decode('utf-8', errors='ignore')
            if request:
                first_line = request.split('\n')[0].strip()
                logger.info(f"HTTP Request from {addr[0]}: {first_line}")
                log_attack("HTTP", addr[0], first_line)

            response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>It works!</h1></body></html>"
            client_socket.send(response.encode('utf-8'))
        except Exception as e:
            logger.error(f"Error handling HTTP client {addr}: {e}")
        finally:
            client_socket.close()

    def stop(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        if self.executor:
            self.executor.shutdown(wait=False)

# --- SSH Honeypot ---
HOST_KEY = paramiko.RSAKey.generate(2048)

class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.attempts = 0

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        return True

    def check_auth_password(self, username, password):
        self.attempts += 1
        logger.info(f"SSH Login attempt #{self.attempts} from {self.client_addr[0]}: user='{username}', password='{password}'")
        
        # Log every attempt
        log_attack("SSH_LOGIN", self.client_addr[0], f"user={username} pass={password} (Attempt {self.attempts})")
        
        # Succeed on 3rd attempt (Fail 2 times) to match default client limits
        if self.attempts < 3:
            return paramiko.AUTH_FAILED
            
        return paramiko.AUTH_SUCCESSFUL

class SSHHoneypot:
    def __init__(self, host='0.0.0.0', port=2222, max_workers=50):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.server_socket = None
        self.is_running = False
        self.executor = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            logger.info(f"SSH Honeypot running on {self.host}:{self.port} with {self.max_workers} workers")

            while self.is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    self.executor.submit(self.handle_client, client_socket, addr)
                except OSError:
                    break
        except Exception as e:
            logger.error(f"Failed to start SSH Honeypot: {e}")

    def handle_client(self, client_socket, addr):
        logger.info(f"SSH Connection from {addr[0]}:{addr[1]}")
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(HOST_KEY)
        server = SSHServerInterface(addr)
        try:
            transport.start_server(server=server)
            chan = transport.accept(20)
            if chan is None:
                pass
            else:
                shell = FakeShell(chan, addr[0])
                shell.start()
        except Exception as e:
            logger.error(f"Error handling SSH client {addr}: {e}")
        finally:
            transport.close()

    def stop(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        if self.executor:
            self.executor.shutdown(wait=False)

# --- Telnet Honeypot ---
class TelnetHoneypot:
    def __init__(self, host='0.0.0.0', port=2323, max_workers=50):
        self.host = host
        self.port = port
        self.max_workers = max_workers
        self.server_socket = None
        self.is_running = False
        self.executor = None

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers)

        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            logger.info(f"Telnet Honeypot running on {self.host}:{self.port} with {self.max_workers} workers")

            while self.is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    self.executor.submit(self.handle_client, client_socket, addr)
                except OSError:
                    break
        except Exception as e:
            logger.error(f"Failed to start Telnet Honeypot: {e}")

    def handle_client(self, client_socket, addr):
        logger.info(f"Telnet Connection from {addr[0]}:{addr[1]}")
        try:
            client_socket.send(b"Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-74-generic x86_64)\r\n")
            client_socket.send(b"login: ")
            
            username = b""
            while True:
                data = client_socket.recv(1)
                if not data or data == b'\n' or data == b'\r':
                    break
                username += data
            
            client_socket.send(b"\r\nPassword: ")
            password = b""
            while True:
                data = client_socket.recv(1)
                if not data or data == b'\n' or data == b'\r':
                    break
                password += data
            
            logger.info(f"Telnet Login attempt from {addr[0]}: user='{username.decode('utf-8', 'ignore')}', password='{password.decode('utf-8', 'ignore')}'")
            log_attack("TELNET_LOGIN", addr[0], f"user={username.decode('utf-8', 'ignore')} pass={password.decode('utf-8', 'ignore')}")

            client_socket.send(b"\r\n")
            shell = FakeShell(client_socket, addr[0])
            shell.start()
        except Exception as e:
            logger.error(f"Error handling Telnet client {addr}: {e}")
        finally:
            client_socket.close()

    def stop(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
        if self.executor:
            self.executor.shutdown(wait=False)

# --- Main Execution ---
def main():
    logger.info("Starting Single-File Honeypot...")

    http_honeypot = HTTPHoneypot(port=8080)
    ssh_honeypot = SSHHoneypot(port=2222)
    telnet_honeypot = TelnetHoneypot(port=2323)

    services = [http_honeypot, ssh_honeypot, telnet_honeypot]
    threads = []

    for service in services:
        t = threading.Thread(target=service.start, daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping Honeypot...")
        for service in services:
            service.stop()
        sys.exit(0)

if __name__ == "__main__":
    main()
