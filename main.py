import socket
from api import app, start_services

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
    # Start all honeypot services by default
    start_services()
    
    local_ip = get_local_ip()
    print("\n" + "="*50)
    print("HONEYPOT NEXUS DASHBOARD")
    print("="*50)
    print("  Local Access:   http://localhost:5050")
    print(f"  Network Access: http://{local_ip}:5050")
    print("="*50 + "\n")
    
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
