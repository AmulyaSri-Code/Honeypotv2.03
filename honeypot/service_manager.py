import threading
import time
import logging

logger = logging.getLogger('service_manager')

class ServiceManager:
    def __init__(self):
        self.services = []
        self.threads = []
        self.is_running = False

    def add_service(self, service):
        self.services.append(service)

    def start_all(self):
        self.is_running = True
        logger.info("Starting all services...")
        for service in self.services:
            self._start_service(service)
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self._monitor_services)
        monitor_thread.daemon = True
        monitor_thread.start()

    def _start_service(self, service):
        t = threading.Thread(target=service.start)
        t.daemon = True
        t.start()
        self.threads.append((service, t))

    def _monitor_services(self):
        while self.is_running:
            for i, (service, t) in enumerate(self.threads):
                if not t.is_alive() and service.is_running:
                    logger.warning(f"Service {service.__class__.__name__} died unexpectedly. Restarting...")
                    # In a real scenario, we might need to re-instantiate or reset state
                    # For now, we'll try to restart the thread if the service object supports it
                    # But typically threads can't be restarted. We need to create a new thread.
                    new_t = threading.Thread(target=service.start)
                    new_t.daemon = True
                    new_t.start()
                    self.threads[i] = (service, new_t)
            time.sleep(5)

    def stop_all(self):
        self.is_running = False
        logger.info("Stopping all services...")
        for service in self.services:
            try:
                service.stop()
            except Exception as e:
                logger.error(f"Error stopping service {service.__class__.__name__}: {e}")
