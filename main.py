import threading
import time
import sys
from honeypot.logger import setup_logger
from honeypot.http_server import HTTPHoneypot
from honeypot.ssh_server import SSHHoneypot
from honeypot.telnet_server import TelnetHoneypot

logger = setup_logger('main')

def main():
    logger.info("Starting Honeypot...")

    # Initialize services
    http_honeypot = HTTPHoneypot(port=8080)
    ssh_honeypot = SSHHoneypot(port=2222)
    telnet_honeypot = TelnetHoneypot(port=2323)

    services = [http_honeypot, ssh_honeypot, telnet_honeypot]
    threads = []

    # Start services in separate threads
    for service in services:
        t = threading.Thread(target=service.start)
        t.daemon = True
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
