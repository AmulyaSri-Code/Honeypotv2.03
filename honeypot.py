import threading
import time
import sys
import signal
import logging
import random
from core.logger import HoneypotLogger
from core.session import SessionManager
from services.telnet import TelnetHoneyPot
from services.ssh import SSHHoneyPot

def signal_handler(sig, frame):
    print("\nStopping existing services...")
    sys.exit(0)

def main():
    # Setup signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    print("Starting HoneyPot...")
    logger = HoneypotLogger()
    
    # Enable Paramiko Logging
    paramiko_logger = logging.getLogger("paramiko")
    paramiko_logger.setLevel(logging.DEBUG)
    if logger.logger.handlers:
         paramiko_logger.addHandler(logger.logger.handlers[0]) # Add file handler
    
    session_manager = SessionManager()

    # Initialize Services
    telnet_service = TelnetHoneyPot(port=2323, logger=logger, session_manager=session_manager)
    ssh_service = SSHHoneyPot(port=2222, logger=logger, session_manager=session_manager)

    # Start Services in separate threads
    telnet_thread = threading.Thread(target=telnet_service.start)
    telnet_thread.daemon = True
    telnet_thread.start()

    ssh_thread = threading.Thread(target=ssh_service.start)
    ssh_thread.daemon = True
    ssh_thread.start()

    logger.logger.info("HoneyPot services started. Press Ctrl+C to stop.")

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        signal_handler(None, None)

if __name__ == "__main__":
    main()
