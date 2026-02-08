# Honeypot Deployment Guide

## Single-file mode (recommended)

Use **one file** for everything: SSH, Telnet, FTP, HTTP, Redis + test client.

```bash
# Start server (all services)
python3 honeypot_all.py

# Run SSH test client
python3 honeypot_all.py --test
```

**Default ports:**

| Service | Port |
|---------|------|
| SSH     | 2222 |
| Telnet  | 2323 |
| FTP     | 2121 |
| HTTP    | 8080 |
| Redis   | 6379 |

---

## Run on Ubuntu Server

### 1. Transfer to server

From your local machine:

```bash
scp -r /path/to/Honeypotv2.03 username@your-ubuntu-server-ip:~/honeypot
```

Then SSH in:

```bash
ssh username@your-ubuntu-server-ip
cd ~/honeypot
```

### 2. Install dependencies on Ubuntu

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

### 3. Create virtual environment and install Python packages

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 4. Run the honeypot

**Foreground (for testing):**

```bash
python3 honeypot_all.py
```

**Background (keeps running after you disconnect):**

```bash
nohup python3 honeypot_all.py >> honeypot.log 2>&1 &
```

**Stop it:**

```bash
pkill -f honeypot_all.py
```

### 5. Run as a systemd service (starts on boot, auto-restart)

From your honeypot directory (`~/honeypot`):

```bash
# Replace YOUR_USER with your Ubuntu username and fix paths if needed
sed -e "s|YOUR_USER|$USER|g" -e "s|/home/YOUR_USER/honeypot|$PWD|g" honeypot.service | sudo tee /etc/systemd/system/honeypot.service
sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl start honeypot
```

Or copy and edit manually: `sudo nano /etc/systemd/system/honeypot.service` — set `User=`, `WorkingDirectory=`, and `ExecStart=` (path to `venv/bin/python3` and `honeypot_all.py`).

Useful commands:

```bash
sudo systemctl status honeypot   # check status
sudo systemctl stop honeypot     # stop
sudo systemctl start honeypot    # start
journalctl -u honeypot -f        # follow service logs
```

Application logs (connections, commands) go to `honeypot.log` in the working directory.

### 6. Firewall (optional)

If you use `ufw`, allow the honeypot ports:

```bash
sudo ufw allow 2222/tcp   # SSH honeypot
sudo ufw allow 2323/tcp   # Telnet honeypot
sudo ufw allow 2121/tcp   # FTP honeypot
sudo ufw allow 8080/tcp   # HTTP honeypot
sudo ufw allow 6379/tcp   # Redis honeypot
sudo ufw reload
```

---

## Custom ports and testing

**Server (custom ports):**

```bash
python3 honeypot_all.py --ssh-port 2222 --telnet-port 2323 --ftp-port 2121 --http-port 8080 --redis-port 6379 --log-file honeypot.log
```

**Test client:**

```bash
python3 honeypot_all.py --test --host 127.0.0.1 --port 2222 -v
```

---

## Multi-file mode (legacy)

If you prefer the original layout:

```bash
python3 honeypot.py
```

Test with:

```bash
python3 test_ssh.py
```

---

## Monitoring

Watch connection and command logs:

```bash
tail -f honeypot.log
```
