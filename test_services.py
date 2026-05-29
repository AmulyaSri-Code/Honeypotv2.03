import socket
import paramiko
import urllib.request
import urllib.error
import ftplib
import time
import argparse

def probe_ssh(host, port=2222):
    print(f"[*] Testing SSH (Port {port})...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(host, port=port, username="root", password="password", timeout=3)
            print("    [+] SSH Connected successfully!")
            
            # Send a dummy command
            stdin, stdout, stderr = client.exec_command("whoami")
            out = stdout.read().decode('utf-8').strip()
            print(f"    [+] Command 'whoami' output: {out}")
        finally:
            client.close()
    except Exception as e:
        print(f"    [-] SSH test failed: {e}")

def probe_ftp(host, port=2121):
    print(f"[*] Testing FTP (Port {port})...")
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=3)
        try:
            # Attempt to login using anonymous credentials
            ftp.login("anonymous", "test@test.com")
            print("    [+] FTP Connected successfully!")
            
            try:
                ftp.retrlines('LIST')
            except Exception:
                pass # Expected to fail if honeypot doesn't implement a real filesystem
        finally:
            ftp.quit()
    except Exception as e:
        print(f"    [-] FTP test failed: {e}")

def probe_http(host, port=8080):
    print(f"[*] Testing HTTP (Port {port})...")
    url = f"http://{host}:{port}/wp-admin"
    try:
        req = urllib.request.Request(url, method="GET")
        response = urllib.request.urlopen(req, timeout=3)
        print(f"    [+] HTTP Connected successfully. Status Code: {response.getcode()}")
    except urllib.error.HTTPError as e:
        # Honeypot might return a 404, 401, or 500 which is fine, we still connected
        print(f"    [+] HTTP Connected successfully. Status Code: {e.code}")
    except Exception as e:
        print(f"    [-] HTTP test failed: {e}")

def probe_telnet(host, port=2323):
    print(f"[*] Testing Telnet (Port {port})...")
    try:
        # Using raw socket to avoid dependency on deprecated telnetlib
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
            print("    [+] Telnet connected successfully!")
            
            try:
                s.recv(1024) # Read initial banner/prompt
            except socket.timeout:
                pass
                
            s.sendall(b"root\n")
            time.sleep(0.5)
            s.sendall(b"password\n")
            time.sleep(0.5)
            s.sendall(b"ls -la\n")
            
            try:
                res = s.recv(1024)
                if res:
                    print(f"    [+] Telnet output: {res.decode('utf-8', errors='ignore').strip()}")
            except socket.timeout:
                pass
    except Exception as e:
        print(f"    [-] Telnet test failed: {e}")

def probe_nc(host, port=4444):
    print(f"[*] Testing NC / Raw Payload (Port {port})...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((host, port))
            print("    [+] NC Connected successfully!")
            s.sendall(b"id\n")
            time.sleep(0.5)
            
            try:
                res = s.recv(1024)
                if res:
                    print(f"    [+] NC output: {res.decode('utf-8', errors='ignore').strip()}")
            except socket.timeout:
                pass
    except Exception as e:
        print(f"    [-] NC test failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="Test Honeypot Services")
    parser.add_argument("--host", default="127.0.0.1", help="Target host IP (default: 127.0.0.1)")
    args = parser.parse_args()
    
    print(f"Starting test for Honeypot services on {args.host}...\n")
    probe_ssh(args.host)
    print("-" * 40)
    probe_ftp(args.host)
    print("-" * 40)
    probe_http(args.host)
    print("-" * 40)
    probe_telnet(args.host)
    print("-" * 40)
    probe_nc(args.host)
    print("\nTests completed. Check the Honeypot dashboard to view logged connections!")

if __name__ == "__main__":
    main()
