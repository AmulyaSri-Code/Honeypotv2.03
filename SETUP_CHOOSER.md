# HoneyPot v3 Setup Chooser

Choose the setup path that matches your goal. Keep the dashboard/API private in every path.

| Goal | Best path | Time | Skill | Public exposure |
| --- | --- | ---: | --- | --- |
| Try HoneyPot on your computer | Local lab | 5-10 min | Beginner | None |
| Deploy quickly on a VPS | Docker quick deploy | 10-15 min | Beginner/intermediate | Sensor ports only |
| Protect an existing website | Website sidecar | 20-30 min | Intermediate | Trap paths only |
| Run a standalone decoy | Public decoy VPS | 20-30 min | Intermediate | Intentional sensors |
| Add alerts/reports | Automation add-on | 10-20 min | Intermediate | None required |

## Local lab

Use this when you only want to test locally.

```bash
./scripts/quick_deploy.sh local
.venv/bin/python main.py
```

Open:

```text
http://localhost:5050/login
```

Do not expose ports publicly.

## Docker quick deploy

Use this on a server or VPS with Docker installed.

```bash
HONEYPOT_PUBLIC_URL=https://honeypot-admin.example.com ./scripts/quick_deploy.sh docker
```

Expected result:

- `.env` generated with safe secrets;
- `.deploy-credentials.txt` generated for first login;
- HoneyPot container starts;
- `/api/health` returns HTTP 200.

Dashboard remains private on `127.0.0.1:5050`. Use SSH tunnel, VPN, Tailscale, Cloudflare Access, or a protected reverse proxy for admin access.

## Existing website sidecar

Use this when you have a real website and want to catch suspicious probes without breaking normal users.

Traffic pattern:

```text
normal traffic -> real website backend
trap paths     -> HoneyPot HTTP sensor
admin dashboard -> private HoneyPot dashboard/API
```

Trap paths commonly include:

```text
/.env
/.git
/wp-login.php
/wp-admin
/phpmyadmin
/adminer
/cgi-bin
/server-status
/manager/html
```

Do not route a path to HoneyPot if your real users or admins need that path. WordPress sites, for example, usually should not trap real `/wp-admin` or `/wp-login.php`.

## Public decoy VPS

Use this when the whole server is intentionally a decoy/lab.

```bash
cp .env.example .env
python setup.py
docker compose -f docker-compose.production.yml up --build -d honeypot
```

Expose only intentional sensor ports and keep dashboard private.

## Automation add-on

Use this after the base deployment works.

Options:

- Slack webhook;
- Discord webhook;
- Telegram bot token + chat ID;
- n8n webhook;
- SMTP settings.

Setup is not complete until a real test alert succeeds.
