# Alert Notification Setup

This guide explains how to run `setup.py` for Slack, Discord, Telegram, and n8n alert notifications in the real HoneyPot backend project.

Important: `setup.py` belongs to the backend project:

```text
/Users/amulyasrivastava/Desktop/Honeypotv2.03/setup.py
```

The public Vercel frontend project does not run `setup.py`. Vercel hosts the React website only. Real alerts must run from the backend/VPS/server where HoneyPotv2.03 is running.

## Quick interactive setup

From the backend project folder:

```bash
cd /Users/amulyasrivastava/Desktop/Honeypotv2.03
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python setup.py
```

The script will ask for:

- dashboard admin username
- dashboard admin password
- dashboard bind host
- dashboard port
- whether to enable alerts
- minimum alert severity
- Slack webhook URL, optional
- n8n webhook URL, optional
- Discord webhook URL, optional
- Telegram bot token, optional
- Telegram chat ID, optional

It writes a local `.env` file with owner-only permissions. Do not commit `.env`.

## Non-interactive setup examples

Use this when installing for another user or a VPS.

### Discord alerts

```bash
cd /Users/amulyasrivastava/Desktop/Honeypotv2.03
source .venv/bin/activate
python setup.py --force --non-interactive \
  --admin-user admin \
  --admin-pass 'CHANGE_THIS_STRONG_PASSWORD' \
  --alerts-enabled true \
  --alert-min-severity high \
  --discord-webhook-url 'https://discord.com/api/webhooks/REDACTED/REDACTED'
```

### Slack alerts

```bash
python setup.py --force --non-interactive \
  --admin-user admin \
  --admin-pass 'CHANGE_THIS_STRONG_PASSWORD' \
  --alerts-enabled true \
  --alert-min-severity high \
  --slack-webhook-url 'https://hooks.slack.com/services/REDACTED/REDACTED/REDACTED'
```

### Telegram alerts

```bash
python setup.py --force --non-interactive \
  --admin-user admin \
  --admin-pass 'CHANGE_THIS_STRONG_PASSWORD' \
  --alerts-enabled true \
  --alert-min-severity high \
  --telegram-bot-token 'REDACTED_BOT_TOKEN' \
  --telegram-chat-id 'REDACTED_CHAT_ID'
```

### n8n alerts

First start/import the n8n workflow:

```bash
cd /Users/amulyasrivastava/Desktop/Honeypotv2.03
scripts/setup_n8n.sh
```

Then configure HoneyPot to send alerts to n8n:

```bash
python setup.py --force --non-interactive \
  --admin-user admin \
  --admin-pass 'CHANGE_THIS_STRONG_PASSWORD' \
  --alerts-enabled true \
  --alert-min-severity high \
  --n8n-webhook-url 'http://localhost:5678/webhook/honeypot-v3-alert'
```

If HoneyPot and n8n run inside the same Docker Compose network, use:

```text
http://n8n:5678/webhook/honeypot-v3-alert
```

instead of localhost.

## Start the backend after setup

```bash
cd /Users/amulyasrivastava/Desktop/Honeypotv2.03
source .venv/bin/activate
python main.py
```

Then open the dashboard locally:

```text
http://127.0.0.1:5050
```

## Verify alert configuration

Check provider status through the dashboard or API.

The README documents these endpoints:

```text
GET /api/alerts/status
POST /api/alerts/test
```

Use the dashboard login token/API auth if required by the backend.

## Safety notes

- Keep `.env` private.
- Do not paste real webhook URLs or bot tokens into GitHub, docs, or public chats.
- Keep the dashboard bound to `127.0.0.1` unless protected by VPN/firewall/reverse-proxy auth.
- Enable only the provider you need.
- Use `HONEYPOT_ALERT_MIN_SEVERITY=high` or `critical` first to avoid notification spam.
