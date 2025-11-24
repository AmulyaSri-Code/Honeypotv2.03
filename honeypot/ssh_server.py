import socket
import threading
import paramiko
from .logger import setup_logger

logger = setup_logger('ssh_honeypot')

# Generate a host key (in a real app, load this from a file)
HOST_KEY = paramiko.RSAKey.generate(2048)

class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        logger.info(f"SSH Login attempt from {self.client_addr[0]}: user='{username}', password='{password}'")
        # Always reject to log attempts, or accept to trap further
        # For this simple honeypot, we'll reject after logging
        return paramiko.AUTH_FAILED

class SSHHoneypot:
    def __init__(self, host='0.0.0.0', port=2222):
        self.host = host
        self.port = port
        self.server_socket = None
        self.is_running = False

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.is_running = True
            logger.info(f"SSH Honeypot running on {self.host}:{self.port}")

            while self.is_running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    client_handler = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr)
                    )
                    client_handler.start()
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
            # Wait for auth
            chan = transport.accept(20)
            if chan is None:
                # No channel opened (auth failed or timeout)
                pass
        except Exception as e:
            logger.error(f"Error handling SSH client {addr}: {e}")
        finally:
            transport.close()

    def stop(self):
        self.is_running = False
        if self.server_socket:
            self.server_socket.close()
