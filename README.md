# 🍯 Integrated Honeypot & Dashboard v2.03

A professional-grade, single-file honeypot designed to deceive attackers and visualize their activity in real-time.

## ✨ Features
*   **Fake Shell**: SSH (Port 2222) and Telnet (Port 2323) provide a realistic Ubuntu terminal simulation.
*   **Brute Force Simulation**: SSH rejects the first 2 password attempts to simulate a hardened server, then grants access on the 3rd.
*   **Live Dashboard**: A beautiful, real-time attack feed (Port 8000) showing every keystroke and command.
*   **Database Logging**: All attacks are logged to a local MySQL database.
*   **Cross-Platform**: Works on macOS (Localhost) and Linux Servers (Ubuntu/Fedora).

---

## 🚀 Quick Start (macOS / Localhost)
Use the one-click setup script to install dependencies, start the database, and launch all services.

**1. Run the Setup Script:**
```bash
./setup_and_run.sh
```

**2. Access the Dashboard:**
Open: [http://localhost:8000](http://localhost:8000)

**3. Attack Yourself:**
*   **SSH:** `ssh user@localhost -p 2222` (Fail twice, succeed on 3rd try)
*   **Telnet:** `telnet localhost 2323`

---

## 🌐 Server Deployment (Ubuntu / Fedora)
For deploying to a real VPS or dedicated server.

**1. Install & Run:**
```bash
sudo ./install.sh
```

**2. Start Services:**
The services will start automatically. You can manage them via systemd:
```bash
sudo systemctl start honeypot honeypot-dashboard
```

**3. Access the Dashboard:**
Open: `http://<YOUR_SERVER_IP>:8000`

---

## 🛠️ Configuration
*   **Honeypot Logic**: Edit `single_file_honeypot.py`
*   **Dashboard API**: Edit `dashboard/api.py`
*   **Database Config**: Docker-compose manages the MySQL instance.
