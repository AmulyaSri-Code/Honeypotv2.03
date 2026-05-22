import os
import socket
from api import app, start_services, bootstrap_admin
from app_meta import APP_NAME, APP_VERSION

def get_local_ip():
    try:
        # Create a dummy socket to find the local IP used for external traffic
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0)
            # Doesn't actually connect, just picks the right interface
            s.connect(('10.254.254.254', 1))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"

def main():
    bootstrap_admin()
    # Start all honeypot services by default
    start_services()
    
    local_ip = get_local_ip()
    print("\n" + "="*50)
    print(f"{APP_NAME} DASHBOARD")
    print("="*50)
    print(f"  Version:        {APP_VERSION}")
    print("  Local Access:   http://localhost:5050")
    print(f"  Network Access: http://{local_ip}:5050")
    print("="*50 + "\n")
    
    bind_host = os.environ.get("HONEYPOT_BIND_HOST", "0.0.0.0")
    dashboard_port = int(os.environ.get("HONEYPOT_DASHBOARD_PORT", "5050"))
    app.run(host=bind_host, port=dashboard_port, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
