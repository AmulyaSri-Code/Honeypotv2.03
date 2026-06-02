#!/usr/bin/env python3
"""Interactive setup helper for Honeypotv2.03.

Creates a local .env file with admin credentials, dashboard binding, runtime
limits, and optional Slack/Telegram/Discord/n8n alert settings. The script never
stores secrets anywhere except the target .env file and sets that file to 0600.
"""
from __future__ import annotations

import argparse
import getpass
import os
import secrets
import stat
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

DEFAULTS = {
    "HONEYPOT_TOKEN_TTL_SECONDS": "28800",
    "HONEYPOT_RATE_LIMIT_PER_MIN": "240",
    "HONEYPOT_TRUSTED_PROXIES": "127.0.0.1",
    "HONEYPOT_MAX_CAPTURE_CHARS": "2048",
    "HONEYPOT_SOCKET_TIMEOUT_SECONDS": "60",
    "HONEYPOT_MAX_CONNECTIONS_PER_SERVICE": "100",
    "HONEYPOT_MAX_CONNECTIONS_PER_IP": "10",
    "HONEYPOT_ALERT_MIN_SEVERITY": "high",
    "HONEYPOT_ALERT_MIN_INTERVAL_SECONDS": "10",
    "HONEYPOT_BIND_HOST": "127.0.0.1",
    "HONEYPOT_SENSOR_BIND_HOST": "127.0.0.1",
    "HONEYPOT_DASHBOARD_PORT": "5050",
    "FLASK_ENV": "production",
    "HONEYPOT_PUBLIC_URL": "http://localhost:5050",
}


BAD_PASSWORDS = {"", "secret", "password", "admin", "admin123", "change_this_now", "replace_with_a_strong_password"}
VALID_SEVERITIES = {"low", "medium", "mid", "high", "critical"}


def normalize_bool(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "true" if str(value).strip().lower() in {"1", "true", "yes", "on", "y"} else "false"



def infer_domain(public_url: str) -> str:
    value = (public_url or "").strip()
    if not value:
        return "localhost"
    candidate = value if "://" in value else f"https://{value}"
    parsed = urlparse(candidate)
    host = parsed.hostname or value.split("/")[0].split(":")[0]
    return host or "localhost"

def validate_admin_credentials(admin_user: str, admin_pass: str) -> None:
    if len(admin_user.strip()) < 3:
        raise ValueError("Admin username must be at least 3 characters.")
    if admin_pass.strip().lower() in BAD_PASSWORDS or len(admin_pass) < 12:
        raise ValueError("Admin password must be at least 12 characters and not a known default.")


def validate_port(port: str) -> str:
    try:
        parsed = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("Dashboard port must be an integer.") from exc
    if parsed < 1 or parsed > 65535:
        raise ValueError("Dashboard port must be between 1 and 65535.")
    return str(parsed)


def build_env_config(
    admin_user: str = "admin",
    admin_pass: Optional[str] = None,
    bind_host: str = DEFAULTS["HONEYPOT_BIND_HOST"],
    sensor_bind_host: str = DEFAULTS["HONEYPOT_SENSOR_BIND_HOST"],
    dashboard_port: str = DEFAULTS["HONEYPOT_DASHBOARD_PORT"],
    alerts_enabled: object = False,
    alert_min_severity: str = DEFAULTS["HONEYPOT_ALERT_MIN_SEVERITY"],
    slack_webhook_url: str = "",
    n8n_webhook_url: str = "",
    discord_webhook_url: str = "",
    telegram_bot_token: str = "",
    telegram_chat_id: str = "",
    trusted_proxies: str = DEFAULTS["HONEYPOT_TRUSTED_PROXIES"],
    token_ttl_seconds: str = DEFAULTS["HONEYPOT_TOKEN_TTL_SECONDS"],
    rate_limit_per_min: str = DEFAULTS["HONEYPOT_RATE_LIMIT_PER_MIN"],
    max_capture_chars: str = DEFAULTS["HONEYPOT_MAX_CAPTURE_CHARS"],
    socket_timeout_seconds: str = DEFAULTS["HONEYPOT_SOCKET_TIMEOUT_SECONDS"],
    max_connections_per_service: str = DEFAULTS["HONEYPOT_MAX_CONNECTIONS_PER_SERVICE"],
    max_connections_per_ip: str = DEFAULTS["HONEYPOT_MAX_CONNECTIONS_PER_IP"],
    public_url: str = DEFAULTS["HONEYPOT_PUBLIC_URL"],
    domain: str = "",
) -> Dict[str, str]:
    if admin_pass is None:
        admin_pass = secrets.token_urlsafe(18)
    admin_user = admin_user.strip()
    validate_admin_credentials(admin_user, admin_pass)

    severity = alert_min_severity.strip().lower()
    public_url = (public_url or DEFAULTS["HONEYPOT_PUBLIC_URL"]).strip()
    detected_domain = (domain or infer_domain(public_url)).strip()
    if severity not in VALID_SEVERITIES:
        raise ValueError(f"Alert minimum severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}.")

    config = {
        "HONEYPOT_ADMIN_USER": admin_user,
        "HONEYPOT_ADMIN_PASS": admin_pass,
        "HONEYPOT_AUTH_SECRET": secrets.token_urlsafe(48),
        "HONEYPOT_TOKEN_TTL_SECONDS": str(int(token_ttl_seconds)),
        "HONEYPOT_RATE_LIMIT_PER_MIN": str(int(rate_limit_per_min)),
        "HONEYPOT_TRUSTED_PROXIES": trusted_proxies.strip(),
        "HONEYPOT_MAX_CAPTURE_CHARS": str(int(max_capture_chars)),
        "HONEYPOT_SOCKET_TIMEOUT_SECONDS": str(int(socket_timeout_seconds)),
        "HONEYPOT_MAX_CONNECTIONS_PER_SERVICE": str(int(max_connections_per_service)),
        "HONEYPOT_MAX_CONNECTIONS_PER_IP": str(int(max_connections_per_ip)),
        "HONEYPOT_ALERTS_ENABLED": normalize_bool(alerts_enabled),
        "HONEYPOT_ALERT_MIN_SEVERITY": severity,
        "HONEYPOT_ALERT_MIN_INTERVAL_SECONDS": DEFAULTS["HONEYPOT_ALERT_MIN_INTERVAL_SECONDS"],
        "SLACK_WEBHOOK_URL": slack_webhook_url.strip(),
        "N8N_WEBHOOK_URL": n8n_webhook_url.strip(),
        "DISCORD_WEBHOOK_URL": discord_webhook_url.strip(),
        "TELEGRAM_BOT_TOKEN": telegram_bot_token.strip(),
        "TELEGRAM_CHAT_ID": telegram_chat_id.strip(),
        "HONEYPOT_BIND_HOST": bind_host.strip() or DEFAULTS["HONEYPOT_BIND_HOST"],
        "HONEYPOT_SENSOR_BIND_HOST": sensor_bind_host.strip() or DEFAULTS["HONEYPOT_SENSOR_BIND_HOST"],
        "HONEYPOT_DASHBOARD_PORT": validate_port(str(dashboard_port)),
        "HONEYPOT_ALLOW_DEFAULT_ADMIN": "false",
        "HONEYPOT_COOKIE_SECURE": "false",
        "HONEYPOT_PUBLIC_URL": public_url,
        "HONEYPOT_DOMAIN": detected_domain,
        "FLASK_ENV": "production",
    }
    return config


def format_env(config: Dict[str, str]) -> str:
    lines = [
        "# Honeypotv2.03 generated configuration",
        "# Generated by setup.py. Do not commit real secrets.",
        "",
        "# Dashboard admin account (required before anyone can open the private dashboard)",
    ]
    ordered_keys = [
        "HONEYPOT_ADMIN_USER",
        "HONEYPOT_ADMIN_PASS",
        "HONEYPOT_AUTH_SECRET",
        "HONEYPOT_TOKEN_TTL_SECONDS",
        "HONEYPOT_RATE_LIMIT_PER_MIN",
        "HONEYPOT_TRUSTED_PROXIES",
        "HONEYPOT_MAX_CAPTURE_CHARS",
        "HONEYPOT_SOCKET_TIMEOUT_SECONDS",
        "HONEYPOT_MAX_CONNECTIONS_PER_SERVICE",
        "HONEYPOT_MAX_CONNECTIONS_PER_IP",
        "HONEYPOT_ALERTS_ENABLED",
        "HONEYPOT_ALERT_MIN_SEVERITY",
        "HONEYPOT_ALERT_MIN_INTERVAL_SECONDS",
        "SLACK_WEBHOOK_URL",
        "N8N_WEBHOOK_URL",
        "DISCORD_WEBHOOK_URL",
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "HONEYPOT_BIND_HOST",
        "HONEYPOT_SENSOR_BIND_HOST",
        "HONEYPOT_DASHBOARD_PORT",
        "HONEYPOT_ALLOW_DEFAULT_ADMIN",
        "HONEYPOT_COOKIE_SECURE",
        "HONEYPOT_PUBLIC_URL",
        "HONEYPOT_DOMAIN",
        "FLASK_ENV",
    ]
    for key in ordered_keys:
        if key == "HONEYPOT_ALERTS_ENABLED":
            lines.extend(["", "# Optional outbound alert delivery"])
        if key == "HONEYPOT_BIND_HOST":
            lines.extend(["", "# Dashboard/API binding"])
        if key == "HONEYPOT_PUBLIC_URL":
            lines.extend(["", "# Public deployment metadata used by docs, health summaries, and reverse proxies"])
        lines.append(f"{key}={config.get(key, '')}")
    return "\n".join(lines) + "\n"


def write_env_file(path: Path, config: Dict[str, str], force: bool = False) -> Path:
    path = Path(path)
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists. Use --force to overwrite it.")
    path.write_text(format_env(config))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    return path


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default


def ask_password(admin_user: str = "admin") -> str:
    while True:
        password = getpass.getpass("Dashboard admin password (12+ chars, no defaults): ")
        confirm = getpass.getpass("Confirm dashboard admin password: ")
        if password != confirm:
            print("Passwords did not match. Try again.")
            continue
        validate_admin_credentials(admin_user, password)
        return password


def interactive_config() -> Dict[str, str]:
    print("Honeypotv2.03 setup: create a local .env configuration")
    admin_user = ask("Dashboard admin username", "admin")
    while True:
        try:
            admin_pass = ask_password(admin_user)
            validate_admin_credentials(admin_user, admin_pass)
            break
        except ValueError as exc:
            print(f"Invalid password: {exc}")
    bind_host = ask("Dashboard bind host", DEFAULTS["HONEYPOT_BIND_HOST"])
    sensor_bind_host = ask("Sensor bind host", DEFAULTS["HONEYPOT_SENSOR_BIND_HOST"])
    dashboard_port = ask("Dashboard port", DEFAULTS["HONEYPOT_DASHBOARD_PORT"])
    alerts_enabled = ask("Enable Slack/Telegram/Discord/n8n alerts? yes/no", "no")
    alert_min_severity = ask("Minimum alert severity", DEFAULTS["HONEYPOT_ALERT_MIN_SEVERITY"])
    slack = ask("Slack webhook URL (optional)", "")
    n8n = ask("n8n webhook URL (optional)", "")
    discord = ask("Discord webhook URL (optional)", "")
    telegram_token = ask("Telegram bot token (optional)", "")
    telegram_chat = ask("Telegram chat ID (optional)", "")
    public_url = ask("Public dashboard URL/domain", DEFAULTS["HONEYPOT_PUBLIC_URL"])
    return build_env_config(
        admin_user=admin_user,
        admin_pass=admin_pass,
        bind_host=bind_host,
        sensor_bind_host=sensor_bind_host,
        dashboard_port=dashboard_port,
        alerts_enabled=alerts_enabled,
        alert_min_severity=alert_min_severity,
        slack_webhook_url=slack,
        n8n_webhook_url=n8n,
        discord_webhook_url=discord,
        telegram_bot_token=telegram_token,
        telegram_chat_id=telegram_chat,
        public_url=public_url,
    )



def setup_success_summary(config: Dict[str, str], output_path: Path) -> str:
    dashboard_url = config.get("HONEYPOT_PUBLIC_URL") or f"http://localhost:{config.get('HONEYPOT_DASHBOARD_PORT', '5050')}"
    domain = config.get("HONEYPOT_DOMAIN") or infer_domain(dashboard_url)
    alerts_state = "enabled" if normalize_bool(config.get("HONEYPOT_ALERTS_ENABLED", "false")) == "true" else "disabled"
    return "\n".join([
        "Successfully setup HoneyPot v3.",
        f"Configuration file: {output_path}",
        f"Dashboard URL: {dashboard_url}",
        f"Detected domain: {domain}",
        f"Dashboard username: {config['HONEYPOT_ADMIN_USER']}",
        f"Alert connections: {alerts_state} (can also be updated from the dashboard Alerts panel)",
        "Next: start the app, open /login, then sign in to the private dashboard.",
    ])

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create Honeypotv2.03 .env configuration")
    parser.add_argument("--output", default=".env", help="Path to write, default: .env")
    parser.add_argument("--force", action="store_true", help="Overwrite existing output file")
    parser.add_argument("--non-interactive", action="store_true", help="Use flags/defaults without prompting")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-pass", default=None, help="Admin password; required in non-interactive mode")
    parser.add_argument("--bind-host", default=DEFAULTS["HONEYPOT_BIND_HOST"], help="Dashboard/API bind host")
    parser.add_argument("--sensor-bind-host", default=DEFAULTS["HONEYPOT_SENSOR_BIND_HOST"], help="Honeypot sensor bind host")
    parser.add_argument("--dashboard-port", default=DEFAULTS["HONEYPOT_DASHBOARD_PORT"])
    parser.add_argument("--alerts-enabled", default="false")
    parser.add_argument("--alert-min-severity", default=DEFAULTS["HONEYPOT_ALERT_MIN_SEVERITY"])
    parser.add_argument("--slack-webhook-url", default="")
    parser.add_argument("--n8n-webhook-url", default="")
    parser.add_argument("--discord-webhook-url", default="")
    parser.add_argument("--telegram-bot-token", default="")
    parser.add_argument("--telegram-chat-id", default="")
    parser.add_argument("--public-url", default=DEFAULTS["HONEYPOT_PUBLIC_URL"], help="Public dashboard URL or domain after reverse-proxy/DNS setup")
    parser.add_argument("--domain", default="", help="Domain name; inferred from --public-url when omitted")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.non_interactive:
        if args.admin_pass is None:
            raise SystemExit("--admin-pass is required in --non-interactive mode so credentials are never printed to stdout.")
        config = build_env_config(
            admin_user=args.admin_user,
            admin_pass=args.admin_pass,
            bind_host=args.bind_host,
            sensor_bind_host=args.sensor_bind_host,
            dashboard_port=args.dashboard_port,
            alerts_enabled=args.alerts_enabled,
            alert_min_severity=args.alert_min_severity,
            slack_webhook_url=args.slack_webhook_url,
            n8n_webhook_url=args.n8n_webhook_url,
            discord_webhook_url=args.discord_webhook_url,
            telegram_bot_token=args.telegram_bot_token,
            telegram_chat_id=args.telegram_chat_id,
            public_url=args.public_url,
            domain=args.domain,
        )
    else:
        config = interactive_config()

    output = write_env_file(Path(args.output), config, force=args.force)
    print(setup_success_summary(config, output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
