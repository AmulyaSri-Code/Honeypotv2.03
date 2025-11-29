import socket
import threading
import logging
import sys
import time
import concurrent.futures
import paramiko
import os

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

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logger.info(f"SSH Login attempt from {self.client_addr[0]}: user='{username}', password='{password}'")
        return paramiko.AUTH_FAILED

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
            
            client_socket.send(b"\r\nLogin incorrect\r\n")
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
