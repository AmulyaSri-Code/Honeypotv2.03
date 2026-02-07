import paramiko
import time
import sys

def test_ssh():
    ip = '127.0.0.1'
    port = 2222
    user = 'admin'
    password = 'password'

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        print(f"Connecting to {ip}:{port}...")
        client.connect(ip, port=port, username=user, password=password)
        print("Connected!")

        shell = client.invoke_shell()
        print("Shell invoked.")
        
        # Receive welcome message
        while not shell.recv_ready():
            time.sleep(0.1)
        print(f"Welcome: {shell.recv(1024).decode()}")

        commands = ["ls", "pwd", "whoami", "exit"]
        for cmd in commands:
            print(f"Sending: {cmd}")
            shell.send(cmd + "\n")
            time.sleep(0.5)
            if shell.recv_ready():
                output = shell.recv(4096).decode()
                print(f"Output: {output}")

        client.close()
        print("Test passed.")

    except Exception as e:
        print(f"Test failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_ssh()
