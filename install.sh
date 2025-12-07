#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Starting Honeypot Installation...${NC}"

# Check Root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root${NC}"
  exit 1
fi

# Detect OS
OS=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo -e "${RED}Cannot detect OS. /etc/os-release missing.${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS${NC}"

# Install Dependencies
if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
    echo "Installing dependencies for Debian/Ubuntu..."
    apt-get update
    apt-get install -y python3-pip docker.io docker-compose curl
elif [[ "$OS" == "fedora" || "$OS" == "centos" || "$OS" == "rhel" ]]; then
    echo "Installing dependencies for Fedora/CentOS..."
    dnf install -y python3-pip docker docker-compose curl
    systemctl enable --now docker
else
    echo -e "${RED}Unsupported OS: $OS${NC}"
    exit 1
fi

# Python Requirements
echo -e "${GREEN}Installing Python libraries...${NC}"
pip3 install -r requirements.txt --break-system-packages || pip install -r requirements.txt --break-system-packages

# Database Setup
echo -e "${GREEN}Starting Database...${NC}"
docker-compose up -d
echo "Waiting for MySQL to initialize..."
sleep 10
# Initialize schema if needed (using python script)
python3 -c "import mysql.connector; import time; time.sleep(5); cnx = mysql.connector.connect(user='honeypot', password='honeypot_password', database='honeypot_logs', host='127.0.0.1'); cur = cnx.cursor(); cur.execute('CREATE TABLE IF NOT EXISTS logs (id INT AUTO_INCREMENT PRIMARY KEY, timestamp DATETIME, service VARCHAR(50), source_ip VARCHAR(50), payload TEXT)'); cnx.commit(); print('Schema Initialized')"

# Systemd Services
WORKING_DIR=$(pwd)
USER_NAME=$(logname || echo $SUDO_USER || echo root)

echo -e "${GREEN}Creating Systemd Services...${NC}"

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

# Enable Services
systemctl daemon-reload
systemctl enable honeypot
systemctl enable honeypot-dashboard


# Get IP Address
SERVER_IP=$(hostname -I | awk '{print $1}')
if [ -z "$SERVER_IP" ]; then
    SERVER_IP="localhost"
fi

echo -e "${GREEN}Services Installed!${NC}"
echo "Start them now with:"
echo "  systemctl start honeypot"
echo "  systemctl start honeypot-dashboard"

echo ""
echo "================================================================"
echo -e "${GREEN}   HONEYPOT DEPLOYMENT SUMMARY   ${NC}"
echo "================================================================"
echo -e "   Server IP:  ${GREEN}$SERVER_IP${NC}"
echo ""
echo -e "   🛡️  Services Running:"
echo -e "      - HTTP:    http://$SERVER_IP:8080"
echo -e "      - SSH:     ssh user@$SERVER_IP -p 2222"
echo -e "      - Telnet:  telnet $SERVER_IP 2323"
echo ""
echo -e "   📊 Dashboard Access:"
echo -e "      - URL:     http://$SERVER_IP:8000"
echo "================================================================"
echo -e "${GREEN}Installation Complete!${NC}"
