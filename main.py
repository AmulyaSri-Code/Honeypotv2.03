"""Launch honeypot and dashboard API"""
from api import app, start_services
import threading

def main():
    # Start all honeypot services by default
    start_services()
    print("Honeypot services started. Starting dashboard API...")
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)

if __name__ == "__main__":
    main()
