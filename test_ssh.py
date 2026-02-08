#!/usr/bin/env python3
"""
SSH Honeypot test client – connect, run commands, and verify the honeypot responds.
Supports CLI args, env vars, config file, retries, timeouts, and custom commands.
"""

import argparse
import os
import sys
import time
from pathlib import Path


# --- Defaults (overridable by env, config, or CLI) ---
DEFAULT_HOST = os.environ.get("SSH_TEST_HOST", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("SSH_TEST_PORT", "2222"))
DEFAULT_USER = os.environ.get("SSH_TEST_USER", "admin")
DEFAULT_PASSWORD = os.environ.get("SSH_TEST_PASSWORD", "password")
DEFAULT_TIMEOUT = int(os.environ.get("SSH_TEST_TIMEOUT", "10"))
DEFAULT_RETRIES = int(os.environ.get("SSH_TEST_RETRIES", "3"))
DEFAULT_COMMANDS = ["ls", "pwd", "whoami", "id", "exit"]


def load_config(path: str) -> dict:
    """Load optional config from JSON or a simple KEY=value file."""
    p = Path(path)
    if not p.exists():
        return {}
    data = {}
    try:
        if p.suffix.lower() == ".json":
            import json
            data = json.loads(p.read_text())
        else:
            for line in p.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    data[k.strip()] = v.strip()
    except Exception:
        pass
    return data


def parse_args():
    # Pre-parse to get --config so we can use it as default source (no -h so main parser handles --help)
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", metavar="PATH")
    pre_args, _ = pre.parse_known_args()
    config = load_config(pre_args.config) if pre_args.config else {}

    def default(key: str, env_default):
        key_lower = key.lower().replace("_", "")
        for k, v in config.items():
            if k.lower().replace("_", "") == key_lower:
                return int(v) if key in ("port", "timeout", "retries") else v
        return env_default

    p = argparse.ArgumentParser(
        description="Test SSH honeypot: connect and run commands.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", default=default("host", DEFAULT_HOST), help="SSH host")
    p.add_argument("--port", type=int, default=default("port", DEFAULT_PORT), help="SSH port")
    p.add_argument("--user", default=default("user", DEFAULT_USER), help="Username")
    p.add_argument("--password", default=default("password", DEFAULT_PASSWORD), help="Password")
    p.add_argument("--timeout", type=int, default=default("timeout", DEFAULT_TIMEOUT), help="Connection/command timeout (seconds)")
    p.add_argument("--retries", type=int, default=default("retries", DEFAULT_RETRIES), help="Connection retry count")
    p.add_argument("--key", metavar="PATH", help="Optional SSH private key path (not used if honeypot only accepts password)")
    p.add_argument("--commands", nargs="*", help="Commands to run (default: ls pwd whoami id exit)")
    p.add_argument("--commands-file", metavar="PATH", help="Read commands from file (one per line)")
    p.add_argument("--config", metavar="PATH", help="Config file (JSON or KEY=value)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("-q", "--quiet", action="store_true", help="Only print errors and final result")
    p.add_argument("--no-color", action="store_true", help="Disable colored output")
    p.add_argument("--dry-run", action="store_true", help="Print connection params and commands, do not connect")
    return p.parse_args()


def colorize(text: str, code: str, no_color: bool) -> str:
    if no_color:
        return text
    # ANSI codes
    codes = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m", "cyan": "\033[36m", "reset": "\033[0m"}
    c = codes.get(code, "")
    r = codes["reset"]
    return f"{c}{text}{r}" if c else text


def recv_with_timeout(shell, timeout: float, chunk: int = 4096) -> str:
    """Read from shell until no data for timeout seconds."""
    buf = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if shell.recv_ready():
            buf.append(shell.recv(chunk).decode(errors="replace"))
            deadline = time.monotonic() + timeout  # extend on activity
        else:
            time.sleep(0.05)
    return "".join(buf)


def run_commands(shell, commands: list, timeout: float, verbose: bool, quiet: bool, no_color: bool) -> list[tuple[str, str, bool]]:
    """Run commands and return list of (command, output, success)."""
    results = []
    for cmd in commands:
        cmd = cmd.strip()
        if not cmd or cmd.startswith("#"):
            continue
        try:
            if verbose and not quiet:
                print(colorize(f"  Sending: {cmd}", "cyan", no_color))
            shell.send(cmd + "\n")
            time.sleep(0.3)
            out = recv_with_timeout(shell, timeout)
            ok = True
            results.append((cmd, out, ok))
            if verbose and not quiet:
                print(out[:500] + ("..." if len(out) > 500 else ""))
        except Exception as e:
            results.append((cmd, str(e), False))
            if not quiet:
                print(colorize(f"  Error running '{cmd}': {e}", "red", no_color))
    return results


def test_ssh(
    host: str,
    port: int,
    user: str,
    password: str,
    key_path: str | None,
    timeout: int,
    retries: int,
    commands: list[str],
    verbose: bool,
    quiet: bool,
    no_color: bool,
) -> int:
    """
    Connect to SSH, invoke shell, run commands. Returns 0 on success, 1 on connection failure, 2 on shell/command failure.
    """
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for attempt in range(1, retries + 1):
        try:
            if not quiet:
                print(colorize(f"Connecting to {host}:{port} (attempt {attempt}/{retries})...", "cyan", no_color))
            connect_kw = dict(
                hostname=host,
                port=port,
                username=user,
                password=password,
                timeout=timeout,
                allow_agent=False,
                look_for_keys=False,
            )
            if key_path and Path(key_path).exists():
                connect_kw["key_filename"] = key_path
                connect_kw["look_for_keys"] = True
            client.connect(**connect_kw)
            break
        except Exception as e:
            if not quiet:
                print(colorize(f"  Connection failed: {e}", "red", no_color))
            if attempt == retries:
                return 1
            time.sleep(1)

    exit_code = 0
    try:
        if not quiet:
            print(colorize("Connected.", "green", no_color))
        shell = client.invoke_shell()
        shell.settimeout(timeout)

        # Welcome banner
        if shell.recv_ready():
            welcome = recv_with_timeout(shell, 2.0)
            if verbose and not quiet:
                print(colorize("Welcome:", "green", no_color), welcome[:300])
        elif not quiet:
            print("Shell invoked.")

        results = run_commands(shell, commands, float(timeout), verbose, quiet, no_color)
        failed = [(c, o) for c, o, ok in results if not ok]
        if failed:
            exit_code = 2
        if not quiet:
            print(colorize(f"Commands run: {len(results)}, failed: {len(failed)}", "yellow", no_color))
        if exit_code == 0 and not quiet:
            print(colorize("Test passed.", "green", no_color))
        elif exit_code != 0 and not quiet:
            print(colorize("Test had failures.", "red", no_color))

        client.close()
    except Exception as e:
        if not quiet:
            print(colorize(f"Test failed: {e}", "red", no_color))
        return 2

    return exit_code


def main():
    args = parse_args()

    commands = list(args.commands) if args.commands else list(DEFAULT_COMMANDS)
    if args.commands_file:
        path = Path(args.commands_file)
        if path.exists():
            commands = [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.strip().startswith("#")]

    if args.dry_run:
        print(f"Would connect to {args.user}@{args.host}:{args.port} (timeout={args.timeout}s, retries={args.retries})")
        print("Commands:", commands)
        return 0

    exit_code = test_ssh(
        host=args.host,
        port=args.port,
        user=args.user,
        password=args.password,
        key_path=args.key,
        timeout=args.timeout,
        retries=args.retries,
        commands=commands,
        verbose=args.verbose,
        quiet=args.quiet,
        no_color=args.no_color,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
