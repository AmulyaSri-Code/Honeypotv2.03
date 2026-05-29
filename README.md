# HoneyPot v3

HoneyPot v3 is a professional defensive deception and threat-intelligence platform for authorized security labs and owned infrastructure. It runs multiple honeypot listeners, captures attacker telemetry, classifies suspicious commands, and provides a hardened web dashboard for SOC-style triage.

Important: HoneyPot v3 is for defensive monitoring only. Deploy it only on systems you own or are explicitly authorized to monitor. Treat captured payloads, credentials, and logs as hostile data.

## Highlights

- Multi-service honeypot sensors for SSH, FTP, HTTP, Telnet, and raw TCP payloads
- Flask API with token authentication, API keys, audit logs, rate limiting, and security headers
- Premium SOC dashboard with live feed, attack map, risk scoring, ASN reputation pivots, case queue, service matrix, alert status, and analyst workbench
- SQLite event storage with WAL mode for safer concurrent reads/writes
- IP reputation and ASN enrichment with private-IP-safe local handling
- Ticketing/case-management API for SOC triage and external workflow tools
- Daily/weekly report API endpoints for n8n, email, or chat summaries
- ML-assisted command classification using TF-IDF and scikit-learn
- Optional Slack, Discord, Telegram, and n8n automation alert delivery
- Website-backend integration guide for routing suspicious paths from an existing site to HoneyPot v3
- Safer local defaults: dashboard and sensors bind to loopback unless explicitly configured otherwise
- Docker Compose support for local deployment and optional security ecosystem services

## Architecture

Core runtime:

- `main.py` starts the API/dashboard and service sensors
- `api.py` exposes dashboard routes, JSON APIs, auth, alerts, users, keys, and deployment checks
- `honeypot.py` contains the service listener implementations
- `core/` contains database, logging, geolocation, service, and shell helpers
- `services/` contains protocol-specific service modules
- `ml/` contains the training dataset, classifier, vectorizer, and model artifacts
- `dashboard/index.html` is the operator dashboard
- `setup.py` generates a local `.env` configuration

Default ports:

| Component | Port |
| --- | ---: |
| Dashboard/API | 5050 |
| SSH sensor | 2222 |
| FTP sensor | 2121 |
| HTTP sensor | 8080 |
| Telnet sensor | 2323 |
| Raw TCP/NC sensor | 4444 |

## Quick Start

### 1. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Create local configuration

Interactive setup:

```bash
python setup.py
```

Non-interactive setup:

```bash
python setup.py --non-interactive \
  --admin-user operator \
  --admin-pass 'StrongPass123!' \
  --bind-host 127.0.0.1 \
  --dashboard-port 5050
```

The setup helper writes `.env` with owner-only permissions and generates a strong `HONEYPOT_AUTH_SECRET`.

For local-only testing, the built-in dashboard login can be `admin / admin`. For any shared, networked, or production deployment, replace it with a strong password before exposure.

### 3. Train or refresh the ML model

```bash
python ml/train.py
```

### 4. Run HoneyPot v3

```bash
python main.py
```

Open:

```text
http://localhost:5050
```

## Website Backend Integration

HoneyPot v3 can sit behind an existing website as a private sidecar service. The safest pattern is to keep your real website backend responsible for normal user traffic and route only suspicious trap paths to the HoneyPot v3 HTTP sensor.

Recommended flow:

```text
Internet -> reverse proxy -> real website backend
                         -> suspicious paths -> HoneyPot v3 HTTP sensor
                         -> private admin path/VPN -> HoneyPot v3 dashboard
```

Good trap paths include probes such as `/.env`, `/.git`, `/wp-login.php`, `/wp-admin`, `/phpmyadmin`, `/adminer`, `/cgi-bin`, and `/server-status`. Do not route your entire production site to the honeypot unless it is intentionally a decoy/lab property.

A complete backend integration guide is included here:

```text
WEBSITE_BACKEND_INTEGRATION.md
```

It includes Nginx, Caddy, Node.js/Express, Python/Flask-style, and Docker Compose sidecar examples, plus a go-live checklist for website owners.

## Configuration

HoneyPot v3 loads runtime settings from `.env` through `env_loader.py`. Existing process environment variables take priority, which makes Docker, systemd, and secret managers easy to use.

Common variables:

```bash
HONEYPOT_ADMIN_USER=operator
HONEYPOT_ADMIN_PASS=replace_with_a_strong_password
HONEYPOT_AUTH_SECRET=generated_by_setup_py
HONEYPOT_TOKEN_TTL_SECONDS=28800
HONEYPOT_RATE_LIMIT_PER_MIN=240
HONEYPOT_ENRICHMENT_ENABLED=true
HONEYPOT_ENRICHMENT_PROVIDER=ip-api
HONEYPOT_BIND_HOST=127.0.0.1
HONEYPOT_SENSOR_BIND_HOST=127.0.0.1
HONEYPOT_DASHBOARD_PORT=5050
HONEYPOT_ALERTS_ENABLED=false
HONEYPOT_ALERT_MIN_SEVERITY=high
N8N_WEBHOOK_URL=
```

Security guidance:

- Keep `.env`, `honeypot.db`, logs, API keys, bot tokens, webhook URLs, and captured payloads out of git
- Keep `HONEYPOT_BIND_HOST=127.0.0.1` unless the dashboard is behind a firewall, VPN, reverse proxy auth, or equivalent control
- Use `HONEYPOT_SENSOR_BIND_HOST=0.0.0.0` only when intentionally exposing sensors in a controlled lab/network
- Rotate admin passwords, API keys, auth secrets, and alert webhooks regularly

## API Overview

Public endpoints:

- `GET /api/meta`
- `GET /api/health`

Authenticated telemetry endpoints:

- `GET /api/stats`
- `GET /api/connections?limit=100`
- `GET /api/commands?limit=100`
- `GET /api/attacks`
- `GET /api/services`

Auth endpoints:

- `POST /api/auth/bootstrap`
- `POST /api/auth/login`
- `GET /api/auth/me`

Enrichment, cases, and reports:

- `GET /api/threats/summary` includes ASN, reputation, deployment, and case workload rollups
- `GET /api/cases?status=open&limit=100`
- `POST /api/cases`
- `PATCH /api/cases/<id>`
- `GET /api/reports/daily`
- `GET /api/reports/weekly`

Alert endpoints:

- `GET /api/alerts/status`
- `POST /api/alerts/test`

Admin endpoints:

- `POST /api/services/<name>/toggle`
- `GET /api/audit?limit=100`
- `GET /api/users`
- `POST /api/users`
- `POST /api/users/<username>/password`
- `DELETE /api/users/<username>`
- `GET /api/keys`
- `POST /api/keys`
- `POST /api/keys/<id>/revoke`

Example login:

```bash
curl -X POST http://localhost:5050/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"operator","password":"StrongPass123!"}'
```

Example authenticated request:

Use the access token returned by the login endpoint in the HTTP Authorization header for later API calls.

## Alerting

Alert delivery is optional and disabled by default. Configure alerting through `python setup.py` or environment variables.

Supported providers:

- Slack webhook
- Discord webhook
- Telegram bot token and chat ID
- n8n webhook for SOC automation workflows

Provider status endpoints expose safe booleans/metadata only; secret values are never returned by the API.

### n8n Automation

HoneyPot v3 can POST structured alert payloads to an n8n webhook. This is the recommended way to build SOC-style workflows without adding more logic to the honeypot runtime.

Example automation ideas:

- Route critical malware events to Slack, Telegram, Discord, or email
- Create Jira, Linear, GitHub, or ServiceNow incident tickets
- Enrich attacker IPs through reputation APIs before notifying analysts
- Store high-risk events in Sheets, Airtable, Notion, or a case-management database
- Generate daily/weekly security summaries

Report automation can use `GET /api/reports/daily` and `GET /api/reports/weekly`; both endpoints are designed for a viewer API key and include totals, top attackers, top ASNs, categories, and open case counts.

Start local n8n with Docker Compose:

```bash
docker-compose --profile automation up -d n8n
```

Open n8n locally:

```text
http://localhost:5678
```

Import the sample workflow through the n8n UI:

```text
n8n-workflows/honeypot-v3-critical-alert.json
```

Or import it with the n8n CLI inside the Docker container:

```bash
docker cp n8n-workflows/honeypot-v3-critical-alert.json honeypot_n8n:/tmp/honeypot-v3-critical-alert.json
docker exec honeypot_n8n n8n import:workflow --input=/tmp/honeypot-v3-critical-alert.json
docker exec honeypot_n8n n8n update:workflow --id=honeypot-v3-critical-alert-router --active=true
docker compose --profile automation restart n8n
```

The restart ensures n8n registers the production webhook after activation.

The sample workflow exposes this webhook path:

```text
/webhook/honeypot-v3-alert
```

Set HoneyPot v3 to send alerts to it:

```bash
HONEYPOT_ALERTS_ENABLED=true
N8N_WEBHOOK_URL=http://localhost:5678/webhook/honeypot-v3-alert
```

For Docker-based HoneyPot-to-n8n delivery on the same compose network, use the n8n service name:

```bash
N8N_WEBHOOK_URL=http://n8n:5678/webhook/honeypot-v3-alert
```

The n8n payload includes `source`, `summary`, `severity`, `sent_at`, and the original HoneyPot event under `event`.

## Docker

```bash
docker-compose up --build
```

Optional security ecosystem profile:

```bash
docker-compose --profile ecosystem up --build
```

Included ecosystem services can include Elastic Stack, Elasticvue, CyberChef, SpiderFoot, Suricata, and Autoheal depending on the compose profile.

Optional automation profile:

```bash
docker-compose --profile automation up -d n8n
```

## Testing and Quality Checks

Install test tooling if needed:

```bash
python -m pip install pytest beautifulsoup4
```

Run the test suite:

```bash
.venv/bin/python -m pytest -q
```

Run Python syntax checks:

```bash
.venv/bin/python -m compileall -q setup.py env_loader.py api.py honeypot.py notifications.py main.py test_services.py tests
```

Check dashboard JavaScript syntax:

```bash
python - <<'PY'
from bs4 import BeautifulSoup
from pathlib import Path
soup = BeautifulSoup(Path('dashboard/index.html').read_text(), 'html.parser')
for i, script in enumerate(soup.find_all('script')):
    if script.string:
        Path(f'/tmp/honeypot_dashboard_{i}.js').write_text(script.string)
        print(f'/tmp/honeypot_dashboard_{i}.js')
PY
node --check /tmp/honeypot_dashboard_1.js
```

## Manual Sensor Smoke Test

After starting HoneyPot v3, probe the local sensors:

```bash
python test_services.py --host 127.0.0.1
```

Then check the dashboard activity feed and API telemetry.

## Deployment Checklist

- Generate `.env` with `python setup.py`
- Replace demo/local credentials with a strong operator password
- Keep dashboard/API private by default
- Put internet-facing dashboards behind TLS, VPN, firewall rules, or reverse proxy authentication
- Expose sensors only on intended lab/network interfaces
- Configure log rotation for `honeypot.log` and database backup/retention for `honeypot.db`
- Configure alert providers only through environment variables or secret managers
- Run tests and dashboard smoke checks before publishing changes

A hardened deployment guide is included at `PRODUCTION_DEPLOYMENT.md` with firewall, reverse-proxy, Docker, enrichment, n8n, and go-live verification guidance.

## License

See `LICENSE`.
