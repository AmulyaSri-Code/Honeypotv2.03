# Honeypot v2.03 // Advanced Threat Intelligence System

An enterprise-grade, multi-service honeypot architecture designed to capture, classify, and visualize real-time malicious network traffic.

## Architectural Overview

The system is built on a highly concurrent backend that dynamically intercepts attacker payloads and routes them through a Machine Learning classification pipeline before plotting them on a global map.

* **Multi-Service Socket Engine**: Native Python thread-handlers running concurrent listeners for SSH (2222), FTP (2121), HTTP (8080), Telnet (2323), and Raw NC (4444).
* **Machine Learning Pipeline**: A Random Forest classifier powered by `scikit-learn` uses TF-IDF vectorization to natively categorize incoming payloads as `Reconnaissance`, `Malware Attempt`, `Privilege Escalation`, `Brute Force`, or `Benign`.
* **Database Layer**: A single-file SQLite matrix fortified with Write-Ahead Logging (WAL) `PRAGMA journal_mode=WAL` to ensure massive concurrent IO operations without throwing database locks.
* **Frontend Presentation**: A dark-themed Glassmorphism dashboard leveraging `Leaflet.js` and asynchronous `Promise.all` fetching to render global attacks with flawless performance and zero UI blocking. 

---

## Step-by-Step Installation

### 1. Environment Setup
Install the strictly pinned dependencies to guarantee a stable architecture without `pip` resolver conflicts. 
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Train the ML Model
Before launching the server, you **must** compile the vectorizer and the Random Forest model binaries.
```bash
python3 ml/train.py
```
*(This parses `dataset.csv` and generates `model.pkl` and `vectorizer.pkl` natively in the `ml/` directory).*

### 3. Launch the Server
You can launch the entire stack natively, or via Docker. All services and the API Dashboard (port `5050`) will boot automatically.
```bash
# Native Python
python3 main.py

# Docker Environment
touch honeypot.db honeypot.log honeypot_out.log  # Prevent Docker from assuming these files are directories
docker-compose up --build
```
Open `http://localhost:5050` in your web browser.

---

## Presentation & Live Demo Instructions

When presenting, you will want to actively demonstrate the dashboard's ability to track global botnets in real-time. Because testing from your own `localhost` generates no GPS coordinates, the system has a built-in **Demo Location Spoofer** for your loopback address. 

1. Ensure the system is actively running (`python3 main.py`).
2. Open the dashboard at `http://localhost:5050`. 
3. Open a **second terminal window**.
4. Launch the automated, multi-threaded bombardment script to simulate a global attack surface:
```bash
python3 /tmp/hardcore_stress.py
```
*(If you moved the script to your project folder, simply run `python3 hardcore_stress.py`).*

**What happens next?**
The script unleashes 15 simultaneous threads aggressively firing 375+ authentic malware/recon payloads into the honeypot. The backend intercepts the `127.0.0.1` origin and dynamically replaces it with randomized global IP blocks (China, Russia, the US, Brazil, etc.), tricking the dashboard into generating a spectacular real-time visual of a worldwide cyber-attack across six continents!

### API Security
The Dashboard feed acts as a Read-Only REST stream. However, the Node Control toggles are destructive operations securely protected by HTTP Basic Auth. You can log into the UI toggles using these defaults (which can be overridden via `os.environ`):
* **Username**: `admin`
* **Password**: `secret`
