# Honeypot Alert Connectivity

This project supports outbound defensive alerts for high-severity honeypot events.
Secrets are read from environment variables only. Do not hardcode webhooks or bot tokens.

## Environment variables

```bash
HONEYPOT_ALERTS_ENABLED=true
HONEYPOT_ALERT_MIN_SEVERITY=high
HONEYPOT_ALERT_MIN_INTERVAL_SECONDS=10

# Slack incoming webhook
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

# Discord channel webhook
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...

# Telegram bot created with @BotFather, plus destination chat/group ID
TELEGRAM_BOT_TOKEN=123456:bot-token
TELEGRAM_CHAT_ID=123456789
```

## Severity behavior

Default threshold is `high`:

- `critical`: Malware Attempt
- `high`: Brute Force, Privilege Escalation
- `medium`: Recon/scan style categories
- `low`: benign/unclassified events

Only events at or above `HONEYPOT_ALERT_MIN_SEVERITY` are sent.

## Dashboard

The dashboard has an `Alert Channels` panel that shows whether Slack, Telegram, and Discord are configured. Admin users can click `Send Test` to verify connectivity.

API endpoints:

- `GET /api/alerts/status` - authenticated users can see enabled/configured status; secret values are never returned.
- `POST /api/alerts/test` - admin-only test delivery.

## Safety notes

- Keep dashboard/API private behind VPN, reverse proxy auth, or localhost binding.
- Keep `.env` out of git.
- Use dedicated Slack/Discord/Telegram channels for honeypot alerts.
- Outbound alert delivery is best effort and rate-limited per event key so attacker traffic cannot spam channels as easily.
