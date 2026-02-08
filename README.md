# Honeypot Deployment Guide

## 1. Transfer to Server
You can transfer this directory to your Fedora server using `scp` or `rsync`.

**Option A: Using SCP (Secure Copy)**
Run this command from your local machine (Mac):
```bash
scp -r /Users/amulyas/Desktop/Honeypotv2.03 username@your-fedora-server-ip:~/honeypot
```
*Replace `username` and `your-fedora-server-ip` with your actual server details.*

## 2. Setup on Fedora Server
SSH into your server:
```bash
ssh username@your-fedora-server-ip
cd ~/honeypot
```

Install System Dependencies (if needed):
```bash
sudo dnf install python3 python3-pip
```

Create and Activate Virtual Environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

Install Python Dependencies:
```bash
pip install -r requirements.txt
```

## 3. Running the Honeypot
To run the honeypot in the background (so it keeps running after you disconnect):
```bash
nohup python honeypot.py > honeypot.log 2>&1 &
```

To stop it later:
```bash
pkill -f honeypot.py
```

## 4. Monitoring
Watch logs in real-time:
```bash
tail -f honeypot.log
```
