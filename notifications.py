"""Outbound alert delivery for defensive honeypot telemetry.

Providers are configured only through environment variables. Secrets are never
returned by status helpers or dashboard APIs.
"""
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from env_loader import load_env_file

load_env_file()

DEFAULT_TIMEOUT_SECONDS = 5
_DEFAULT_MIN_INTERVAL_SECONDS = 10
_LAST_SENT = {}
_LOCK = threading.Lock()

SEVERITY_RANK = {
    "low": 10,
    "medium": 20,
    "mid": 20,
    "high": 30,
    "critical": 40,
}


def _env_true(name, default="false"):
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


def alerts_enabled():
    return _env_true("HONEYPOT_ALERTS_ENABLED", "false")


def configured_providers():
    providers = []
    if os.environ.get("SLACK_WEBHOOK_URL"):
        providers.append("slack")
    if os.environ.get("DISCORD_WEBHOOK_URL"):
        providers.append("discord")
    if os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"):
        providers.append("telegram")
    return providers


def provider_status():
    return {
        "enabled": alerts_enabled(),
        "min_severity": os.environ.get("HONEYPOT_ALERT_MIN_SEVERITY", "high").lower(),
        "providers": {
            "slack": {"configured": bool(os.environ.get("SLACK_WEBHOOK_URL"))},
            "discord": {"configured": bool(os.environ.get("DISCORD_WEBHOOK_URL"))},
            "telegram": {"configured": bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))},
        },
    }


def severity_for_category(attack_category):
    cat = (attack_category or "").lower()
    if "malware" in cat:
        return "critical"
    if "privilege" in cat or "brute" in cat:
        return "high"
    if "recon" in cat or "scan" in cat:
        return "medium"
    return "low"


def should_alert(event):
    if not alerts_enabled():
        return False
    if not configured_providers():
        return False
    severity = event.get("severity") or severity_for_category(event.get("attack_category"))
    minimum = os.environ.get("HONEYPOT_ALERT_MIN_SEVERITY", "high").lower()
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(minimum, 30)


def format_alert(event):
    severity = (event.get("severity") or severity_for_category(event.get("attack_category"))).upper()
    event_type = event.get("event_type", "honeypot_event")
    service = (event.get("service") or "unknown").upper()
    ip = event.get("ip") or "unknown"
    timestamp = event.get("timestamp") or datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"
    category = event.get("attack_category") or "Unclassified"
    command = event.get("command") or ""
    if len(command) > 300:
        command = command[:285] + "...[truncated]"
    lines = [
        f"[{severity}] Honeypot alert: {event_type}",
        f"Service: {service}",
        f"Source IP: {ip}",
        f"Category: {category}",
        f"Time: {timestamp}",
    ]
    if command:
        lines.append(f"Command/Payload: {command}")
    return "\n".join(lines)


def _post_json(url, payload, timeout=DEFAULT_TIMEOUT_SECONDS):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return 200 <= getattr(resp, "status", 200) < 300


def _send_slack(text):
    return _post_json(os.environ["SLACK_WEBHOOK_URL"], {"text": text})


def _send_discord(text):
    return _post_json(os.environ["DISCORD_WEBHOOK_URL"], {"content": text[:1900]})


def _send_telegram(text):
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    url = f"https://api.telegram.org/bot{urllib.parse.quote(token)}/sendMessage"
    return _post_json(url, {"chat_id": chat_id, "text": text[:3900], "disable_web_page_preview": True})


def _rate_limited(event):
    interval = int(os.environ.get("HONEYPOT_ALERT_MIN_INTERVAL_SECONDS", str(_DEFAULT_MIN_INTERVAL_SECONDS)))
    key = f"{event.get('event_type')}:{event.get('service')}:{event.get('ip')}:{event.get('attack_category')}"
    now = time.time()
    with _LOCK:
        last = _LAST_SENT.get(key, 0)
        if now - last < interval:
            return True
        _LAST_SENT[key] = now
    return False


def send_alert(event):
    """Send one alert synchronously. Returns per-provider success metadata."""
    if not should_alert(event):
        return {"sent": False, "reason": "disabled_or_below_threshold", "providers": {}}
    if _rate_limited(event):
        return {"sent": False, "reason": "rate_limited", "providers": {}}

    text = format_alert(event)
    results = {}
    for provider in configured_providers():
        try:
            if provider == "slack":
                results[provider] = {"ok": bool(_send_slack(text))}
            elif provider == "discord":
                results[provider] = {"ok": bool(_send_discord(text))}
            elif provider == "telegram":
                results[provider] = {"ok": bool(_send_telegram(text))}
        except (urllib.error.URLError, TimeoutError, OSError, KeyError, ValueError) as exc:
            results[provider] = {"ok": False, "error": exc.__class__.__name__}
    return {"sent": any(item.get("ok") for item in results.values()), "providers": results}


def send_alert_async(event, logger=None):
    """Dispatch without blocking honeypot socket handling."""
    if not should_alert(event):
        return False

    def worker():
        result = send_alert(event)
        if logger and result.get("providers"):
            logger.info("Alert delivery result: %s", result)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    return True
