import socket
import threading
from .logger import setup_logger

logger = setup_logger('http_honeypot')

class HTTPHoneypot:
    def __init__(self, host='0.0.0.0', port=8080):
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
            logger.info(f"HTTP Honeypot running on {self.host}:{self.port}")
            
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
            logger.error(f"Failed to start HTTP Honeypot: {e}")

    def handle_client(self, client_socket, addr):
        logger.info(f"HTTP Connection from {addr[0]}:{addr[1]}")
        try:
            request = client_socket.recv(1024).decode('utf-8', errors='ignore')
            if request:
                # Log the first line of the request (e.g., GET / HTTP/1.1)
                first_line = request.split('\n')[0].strip()
                logger.info(f"HTTP Request from {addr[0]}: {first_line}")
                
                # Log headers if needed (simplified for now)
                # logger.debug(f"Full request:\n{request}")

            # Send a fake response
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
