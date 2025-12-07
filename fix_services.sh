#!/bin/bash
# fix_services.sh 
# Run this if install.sh fails to create services

if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root (sudo)"
  exit 1
fi

WORKING_DIR=$(pwd)
# Try to get the real user who ran sudo, otherwise root
USER_NAME=${SUDO_USER:-$USER}

echo "Repairing Systemd Services..."
echo "User: $USER_NAME"
echo "Dir:  $WORKING_DIR"

# Honeypot Service
cat <<EOF > /etc/systemd/system/honeypot.service
[Unit]
Description=Single File Honeypot Service
After=network.target docker.service

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$WORKING_DIR
ExecStart=/usr/bin/python3 $WORKING_DIR/single_file_honeypot.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Dashboard Service
cat <<EOF > /etc/systemd/system/honeypot-dashboard.service
[Unit]
Description=Honeypot Dashboard API
After=network.target

[Service]
Type=simple
User=$USER_NAME
WorkingDirectory=$WORKING_DIR
ExecStart=/usr/bin/python3 -m uvicorn dashboard.api:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Reload and Enable
systemctl daemon-reload
systemctl enable honeypot
systemctl enable honeypot-dashboard

echo "------------------------------------------------"
echo "Services repaired successfully!"
echo "Run this to start them:"
echo "sudo systemctl start honeypot honeypot-dashboard"
echo "------------------------------------------------"
