import random

class FakeShell:
    def __init__(self, distro="ubuntu"):
        self.distro = distro.lower()
        self.cwd = "/home/admin"
        self.username = "admin"
        
        if self.distro == "fedora":
            self.hostname = "localhost.localdomain"
            self.filesystem = {
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
                "/home/admin/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n(FAKE FEDORA KEY)\n-----END OPENSSH PRIVATE KEY-----\n",
                "/proc/version": "Linux version 5.11.12-300.fc34.x86_64 (mockbuild@bkernel02.phx2.fedoraproject.org) (gcc (GCC) 11.0.0 20210210 (Red Hat 11.0.0-0)) #1 SMP Wed Apr 21 13:19:18 UTC 2021\n",
                "/etc/os-release": "NAME=Fedora\nVERSION=\"34 (Server Edition)\"\nID=fedora\nVERSION_ID=34\nPRETTY_NAME=\"Fedora 34 (Server Edition)\"\nANSI_COLOR=\"0;38;2;60;110;180\"\nLOGO=fedora-logo-icon\n",
                "/home/admin/todo.txt": "Update dnf packages.\nCheck firewall rules.\n"
            }
        else: # Default to Ubuntu
            self.hostname = "ubuntu-server"
            self.filesystem = {
                "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:admin:/home/admin:/bin/bash\n",
                "/home/admin/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\n(FAKE UBUNTU KEY)\n-----END OPENSSH PRIVATE KEY-----\n",
                "/proc/version": "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038) (gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020\n",
                "/etc/os-release": "NAME=\"Ubuntu\"\nVERSION=\"20.04.1 LTS (Focal Fossa)\"\nID=ubuntu\nID_LIKE=debian\nPRETTY_NAME=\"Ubuntu 20.04.1 LTS\"\nVERSION_ID=\"20.04\"\nVERSION_CODENAME=focal\nUBUNTU_CODENAME=focal\n",
                "/home/admin/notes.txt": "Server maintenance scheduled for Friday.\nDon't forget to backup the database.\n"
            }
            
        self.valid_commands = ["ls", "pwd", "whoami", "uname", "cat", "help", "exit", "id"]

    def handle_command(self, command_str):
        command_str = command_str.strip()
        if not command_str:
            return ""
        
        parts = command_str.split()
        cmd = parts[0]
        args = parts[1:]

        if cmd == "pwd":
            return self.cwd + "\n"
        
        elif cmd == "whoami":
            return self.username + "\n"
            
        elif cmd == "id":
             return "uid=1000(admin) gid=1000(admin) groups=1000(admin)\n"
        
        elif cmd == "uname":
            if "-a" in args:
                if self.distro == "fedora":
                    return f"Linux {self.hostname} 5.11.12-300.fc34.x86_64 #1 SMP Wed Apr 21 13:19:18 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux\n"
                return f"Linux {self.hostname} 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux\n"
            return "Linux\n"
            
        elif cmd == "ls":
            files = []
            if self.cwd == "/home/admin":
                if self.distro == "fedora":
                    files = ["todo.txt", ".ssh"]
                else:
                    files = ["notes.txt", ".ssh"]
            elif self.cwd == "/etc":
                files = ["passwd", "shadow", "hosts", "os-release"]
            elif self.cwd == "/":
                files = ["bin", "boot", "dev", "etc", "home", "lib", "proc", "root", "sys", "tmp", "usr", "var"]
            return "  ".join(files) + "\n"

        elif cmd == "cat":
            if not args:
                return "cat: missing operand\n"
            target_file = args[0]
            
            if target_file.startswith("/"):
                abs_path = target_file
            else:
                abs_path = f"{self.cwd}/{target_file}".replace("//", "/")
            
            if abs_path in self.filesystem:
                return self.filesystem[abs_path]
            else:
                return f"cat: {target_file}: No such file or directory\n"
        
        elif cmd == "exit":
            return "exit" 

        elif cmd == "help":
             return "GNU bash, version 5.0.17(1)-release (x86_64-pc-linux-gnu)\nThese shell commands are defined internally.  Type `help' to see this list.\n\n ls\n pwd\n whoami\n uname\n cat\n id\n exit\n"

        else:
            return f"{cmd}: command not found\n"
