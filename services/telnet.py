import socket
import threading
from core.session import SessionManager
from core.logger import HoneypotLogger
from core.shell import FakeShell

class TelnetHoneyPot:
    def __init__(self, host='0.0.0.0', port=2323, logger=None, session_manager=None):
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
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr)
                )
                client_handler.start()
        except Exception as e:
            self.logger.logger.error(f"Error starting Telnet Honeypot: {e}")

    def handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "TELNET")
        shell = FakeShell()
        
        try:
            client_sock.send(b"Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n")
            client_sock.send(b"login: ")
            username = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.logger.log_command(session_id, ip, "TELNET", f"LOGIN ATTEMPT: USER={username}")
            
            client_sock.send(b"Password: ")
            password = client_sock.recv(1024).decode('utf-8', errors='ignore').strip()
            self.logger.log_command(session_id, ip, "TELNET", f"LOGIN ATTEMPT: PASS={password}")
            
            client_sock.send(b"\r\nLast login: " + shell.handle_command("date").encode('utf-8') + b"\r\n")
            
            while True:
                prompt = f"{shell.username}@{shell.hostname}:{shell.cwd}$ "
                client_sock.send(prompt.encode('utf-8'))
                
                cmd_bytes = client_sock.recv(1024)
                if not cmd_bytes:
                    break
                
                cmd_str = cmd_bytes.decode('utf-8', errors='ignore').strip()
                if not cmd_str:
                    continue
                
                self.logger.log_command(session_id, ip, "TELNET", cmd_str)
                
                if cmd_str == "exit":
                    break
                
                response = shell.handle_command(cmd_str)
                client_sock.send(response.encode('utf-8'))
                
        except Exception as e:
            self.logger.logger.error(f"Error handling Telnet client {ip}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "TELNET", "Disconnected")
            client_sock.close()
            self.session_manager.end_session(session_id)
