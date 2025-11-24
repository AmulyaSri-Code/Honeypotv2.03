import time
import sys
from honeypot.logger import setup_logger
from honeypot.http_server import HTTPHoneypot
from honeypot.ssh_server import SSHHoneypot
from honeypot.telnet_server import TelnetHoneypot
from honeypot.service_manager import ServiceManager

logger = setup_logger('main')

def main():
    logger.info("Starting Honeypot with Multi-Threaded Architecture...")

    # Initialize Service Manager
    service_manager = ServiceManager()

    # Initialize services
    http_honeypot = HTTPHoneypot(port=8080, max_workers=50)
    ssh_honeypot = SSHHoneypot(port=2222, max_workers=50)
    telnet_honeypot = TelnetHoneypot(port=2323, max_workers=50)

    # Add services to manager
    service_manager.add_service(http_honeypot)
    service_manager.add_service(ssh_honeypot)
    service_manager.add_service(telnet_honeypot)

    # Start all services
    service_manager.start_all()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Stopping Honeypot...")
        service_manager.stop_all()
        sys.exit(0)

if __name__ == "__main__":
    main()
