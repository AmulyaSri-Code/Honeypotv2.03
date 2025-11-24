import socket
import concurrent.futures
from .logger import setup_logger

logger = setup_logger('telnet_honeypot')

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
