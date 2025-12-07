
import sys
import time
import socket
import logging
import mysql.connector

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger()

DB_CONFIG = {
    'host': 'localhost',
    'user': 'honeypot',
    'password': 'honeypot_password',
    'database': 'honeypot_logs'
}

def test_telnet():
    logger.info("Testing Telnet (Port 2323)...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(('localhost', 2323))
        
        # Read Banner
        banner = s.recv(1024).decode()
        if "Ubuntu" not in banner:
            logger.error("Telnet Banner Mismatch")
            return False
            
        # Login
        s.send(b"root\n")
        time.sleep(0.5)
        s.send(b"toor\n")
        time.sleep(0.5)
        
        # Check Shell
        resp = s.recv(1024).decode()
        if "user@ubuntu" not in resp:
            logger.error(f"Telnet Shell Prompt not found. Got: {resp}")
            return False
            
        # Run command
        s.send(b"ls\n")
        time.sleep(1)
        resp = s.recv(4096).decode() # Increased buffer and wait
        logger.info(f"LS Output: {resp}")
        
        if "Documents" not in resp:
             # Try reading again just in case
             time.sleep(0.5)
             resp += s.recv(4096).decode()
             
        if "Documents" not in resp:
             logger.error("Telnet 'ls' command failed")
             return False

        logger.info("Telnet Login & Shell: SUCCESS")
        return True
    except Exception as e:
        logger.error(f"Telnet Test Failed: {e}")
        return False

def check_db_logs():
    logger.info("Checking DB Logs...")
    try:
        cnx = mysql.connector.connect(**DB_CONFIG)
        cursor = cnx.cursor(dictionary=True)
        cursor.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 5")
        rows = cursor.fetchall()
        
        found_telnet = False
        for row in rows:
            logger.info(f"Log Found: {row['service']} - {row['payload']}")
            if row['service'] == "TELNET_LOGIN":
                found_telnet = True
                
        cnx.close()
        
        if found_telnet:
             logger.info("DB Logging: SUCCESS")
             return True
        else:
             logger.error("DB Logging: FAILED (Telnet login not found)")
             return False
    except Exception as e:
        logger.error(f"DB Test Failed: {e}")
        return False

if __name__ == "__main__":
    if test_telnet():
        time.sleep(2) # Wait for flush
        if check_db_logs():
            logger.info("ALL VERIFICATION CHECKS PASSED")
            sys.exit(0)
    
    logger.error("VERIFICATION FAILED")
    sys.exit(1)
