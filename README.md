# Honeypot v2.03

Multi-service honeypot with SSH, FTP, HTTP, Telnet, and Netcat (NC). Logs all connections and commands to SQLite with IP geolocation. **ML-based real-time attack classification** labels each command by attack type. Keeps sessions alive for at least 2 minutes for tracking.

## ML Attack Classification

- **Attack categories:** Reconnaissance, Brute Force, Privilege Escalation, Malware Attempt, Benign
- **Pipeline:** TF-IDF → Logistic Regression (fast real-time prediction)
- **Flow:** Command → ML model → Attack label → Logged in DB and console

### Train the model (run once, or after adding to dataset):
```bash
python ml/train.py
```

### Add your own labeled commands:
Edit `ml/dataset.csv` — add rows: `command,attack_category`

## Services & Ports

| Service | Port | Notes |
|---------|------|-------|
| SSH | 2222 | Fake shell: `ls`, `pwd`, `who`, `whoami`, `id`, `uname` |
| FTP | 2121 | Accepts any login, fake directory listing |
| HTTP | 8080 | Returns HTML page, holds connection 2+ min |
| Telnet | 2323 | Fake shell: same commands as SSH |
| NC (Netcat) | 4444 | Raw TCP, echoes data, holds connection 2+ min |

Ports are non-privileged (no root/admin needed).

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

## Database

- **File:** `honeypot.db` (SQLite)
- **Tables:** `connections` (IP, geo, timestamps), `commands` (all input)
- **Geolocation:** Country, city, region, lat/lon, ISP via ip-api.com

## View Logs

```bash
python view_logs.py
```

Or query SQLite directly:

```sql
SELECT ip, service, country, city, timestamp FROM connections;
SELECT ip, service, command FROM commands;
```

## Fake Shell Commands (SSH/Telnet)

- `ls` - Fake directory listing
- `pwd` - Returns `/home/admin`
- `who` - Fake user sessions
- `whoami` - Random user
- `id`, `uname` - Additional fake responses

## Session Duration

Connections are held for at least 2 minutes (`MIN_SESSION_SECONDS = 120`) to allow IP and geolocation tracking. Idle timeout is 5 minutes.
