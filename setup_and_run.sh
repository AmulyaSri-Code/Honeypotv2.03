#!/bin/bash
# setup_and_run.sh
# One-click setup for Localhost (macOS/Linux)

GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${GREEN}>>> Setting up Honeypot on Localhost...${NC}"

# 1. Install Dependencies
echo "Installing Python requirements..."
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip install -r requirements.txt

# 2. Start Database
echo "Starting MySQL Database..."
docker-compose up -d
echo "Waiting 10s for Database to initialize..."
sleep 10
# Initialize Table
python3 -c "import mysql.connector; import time; cnx = mysql.connector.connect(user='honeypot', password='honeypot_password', database='honeypot_logs', host='127.0.0.1'); cur = cnx.cursor(); cur.execute('CREATE TABLE IF NOT EXISTS logs (id INT AUTO_INCREMENT PRIMARY KEY, timestamp DATETIME, service VARCHAR(50), source_ip VARCHAR(50), payload TEXT)'); cnx.commit(); print('Schema Ready')" 2>/dev/null

# 3. Kill existing instances (to avoid port conflicts)
echo "Stopping any existing instances..."
pkill -f single_file_honeypot.py || true
pkill -f "uvicorn dashboard.api:app" || true
sleep 2

# 4. Start Services
echo -e "${GREEN}>>> Starting Services...${NC}"

# Start Honeypot in background
nohup python3 single_file_honeypot.py > honeypot.log 2>&1 &
HP_PID=$!
echo " - Honeypot started (PID $HP_PID)"

# Start Dashboard in background
nohup python3 -m uvicorn dashboard.api:app --host 0.0.0.0 --port 8000 > dashboard.log 2>&1 &
DB_PID=$!
echo " - Dashboard started (PID $DB_PID)"

echo ""
echo "=================================================="
echo -e "${GREEN}   SYSTEM RUNNING   ${NC}"
echo "=================================================="
echo "   🛡️  Honeypot Active on Ports: 8080, 2222, 2323"
echo "   📊 Dashboard Access: http://localhost:8000"
echo ""
echo "Logs are being written to honeypot.log and dashboard.log"
echo "To stop everything, run: pkill -f python3"
echo "=================================================="
