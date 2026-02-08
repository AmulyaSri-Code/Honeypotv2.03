import threading
import socket
import paramiko
from core.session import SessionManager
from core.logger import HoneypotLogger
from core.shell import FakeShell

# Generate a temporary host key if one doesn't exist
# For a real deployment, we'd load this from a file
HOST_KEY = paramiko.RSAKey.generate(2048)

class FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, ip, session_id, logger):
        self.ip = ip
        self.session_id = session_id
        self.logger = logger
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        self.logger.logger.info(f"SSH: Received channel request {kind} for session {self.session_id}")
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.logger.log_command(self.session_id, self.ip, "SSH", f"LOGIN ATTEMPT: USER={username} PASS={password}")
        # Accept any password
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_shell_request(self, channel):
        self.logger.logger.info(f"SSH: Received shell request for session {self.session_id}")
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        self.logger.logger.info(f"SSH: Received PTY request for session {self.session_id}")
        return True

class SSHHoneyPot:
    def __init__(self, host='0.0.0.0', port=2222, logger=None, session_manager=None):
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
            self.logger.logger.info(f"SSH Honeypot listening on {self.host}:{self.port}")

            while True:
                client_sock, addr = self.server_socket.accept()
                self.logger.log_connection("PENDING", addr[0], "SSH", "Connected")
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, addr)
                )
                client_handler.start()
        except Exception as e:
            self.logger.logger.error(f"Error starting SSH Honeypot: {e}")

            # Test commit

    def handle_client(self, client_sock, addr):
        ip = addr[0]
        session_id = self.session_manager.create_session(ip, "SSH")
        
        try:
            transport = paramiko.Transport(client_sock)
            transport.add_server_key(HOST_KEY)
            
            server = FakeSSHServer(ip, session_id, self.logger)
            try:
                transport.start_server(server=server)
            except paramiko.SSHException:
                return

            channel = transport.accept(20)
            if channel is None:
                return

            # Wait longer for the shell request
            server.event.wait(30)
            if not server.event.is_set():
                self.logger.logger.warning(f"SSH: Timed out waiting for shell request for session {session_id}")
                channel.close()
                return

            shell = FakeShell()
            channel.send(b"Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n")

            while True:
                prompt = f"{shell.username}@{shell.hostname}:{shell.cwd}$ "
                channel.send(prompt)
                
                cmd_data = b""
                while True:
                    char = channel.recv(1)
                    if not char:
                        return
                    # Basic echo and enter handling
                    if char == b'\r':
                        channel.send(b'\r\n')
                        break
                    elif char == b'\x7f': # Backspace
                        channel.send(b'\b \b') # Erase
                        cmd_data = cmd_data[:-1]
                    else:
                        channel.send(char)
                        cmd_data += char
                
                cmd_str = cmd_data.decode('utf-8', errors='ignore').strip()
                
                if cmd_str:
                    self.logger.log_command(session_id, ip, "SSH", cmd_str)
                    
                    if cmd_str == "exit":
                        break
                    
                    response = shell.handle_command(cmd_str)
                    channel.send(response.replace("\n", "\r\n")) # SSH requires CRLF
                
            channel.close()
            
        except Exception as e:
            self.logger.logger.error(f"Error in SSH session {session_id}: {e}")
        finally:
            self.logger.log_connection(session_id, ip, "SSH", "Disconnected")
            self.session_manager.end_session(session_id)
