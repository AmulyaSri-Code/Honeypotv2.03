import logging
import time

class HoneypotLogger:
    def __init__(self, log_file="honeypot.log"):
        self.logger = logging.getLogger("HoneypotLogger")
        self.logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)
        
        # Also print to console
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

    def log_command(self, session_id, ip, service, command):
        """Logs a command execution event."""
        log_entry = f"[Session: {session_id}] [IP: {ip}] [Service: {service}] Command: {command}"
        self.logger.info(log_entry)

    def log_connection(self, session_id, ip, service, status):
        """Logs a connection attempt or status change."""
        log_entry = f"[Session: {session_id}] [IP: {ip}] [Service: {service}] Status: {status}"
        self.logger.info(log_entry)
