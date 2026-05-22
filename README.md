# Honeypot v3.00 // Advanced Threat Intelligence Platform

Honeypot v3.00 is a multi-service defensive deception platform that captures hostile traffic, classifies attack commands with ML, and exposes a hardened API/dashboard for authorized operations and analysis.

**Scope:** this project is for owned, authorized defensive honeypot deployments and security-lab telemetry only. Do not use it to attack third-party systems.

## v3.00 Product Features

- Multi-service honeypot listeners: SSH (`2222`), FTP (`2121`), HTTP (`8080`), Telnet (`2323`), NC (`4444`)
- Flask API and realtime dashboard on `5050`
- ML command classification (TF-IDF + Random Forest via `scikit-learn`)
- SQLite with WAL mode for concurrent writes
- Token auth + API key auth + optional basic-auth fallback for legacy admin actions
- User management, API key lifecycle, audit logs, health checks
- Request throttling and secure response headers for safer public exposure
- First-run `setup.py` helper for safe local `.env` generation
- Slack, Discord, and Telegram alert integrations through environment variables

## Quick Start

### 1) Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2) Train ML model

```bash
python3 ml/train.py
```

### 3) Run first-time setup

Use the setup helper instead of relying on fallback credentials:

```bash
python setup.py
```

If you are using the virtual environment explicitly:

```bash
.venv/bin/python setup.py
```

The setup helper creates a local `.env` file with owner-only permissions (`0600`) and asks for:

- Dashboard/admin username
- Dashboard/admin password
- Dashboard bind host
- Dashboard port
- Alerting options
- Slack, Discord, or Telegram alert settings if enabled

The helper automatically generates `HONEYPOT_AUTH_SECRET` and rejects weak/default admin passwords.

### 4) Run

```bash
python3 main.py
```

Open `http://localhost:5050`.

By default, new setup files bind the dashboard to `127.0.0.1`. Only bind to `0.0.0.0` when the dashboard is protected by a firewall, VPN, reverse proxy auth, or equivalent access control.

## Non-Interactive Setup

For automation, CI, or deployment scripts:

```bash
python setup.py --non-interactive \
  --admin-user operator \
  --admin-pass 'StrongPass123!' \
  --bind-host 127.0.0.1 \
  --dashboard-port 5050
```

Write to a custom file:

```bash
python setup.py --non-interactive \
  --admin-user operator \
  --admin-pass 'StrongPass123!' \
  --output /tmp/honeypot.env
```

Overwrite an existing `.env` only when intentional:

```bash
python setup.py --force
```

## Environment Configuration

Local runtime configuration is loaded from `.env` by `env_loader.py`. Existing process environment variables take priority, so Docker/systemd/Kubernetes secrets can override local `.env` values.

Common variables:

```bash
HONEYPOT_ADMIN_USER=operator
HONEYPOT_ADMIN_PASS=replace_with_a_strong_password
HONEYPOT_AUTH_SECRET=generated_by_setup_py
HONEYPOT_TOKEN_TTL_SECONDS=28800
HONEYPOT_RATE_LIMIT_PER_MIN=240
HONEYPOT_BIND_HOST=127.0.0.1
HONEYPOT_DASHBOARD_PORT=5050
HONEYPOT_ALERTS_ENABLED=false
```

Do not commit `.env`, real passwords, auth secrets, webhook URLs, bot tokens, chat IDs, or local database/log files.

## Alerting

Alert delivery is optional and disabled by default. Configure it through `python setup.py` or environment variables.

Supported providers:

- Slack webhook
- Discord webhook
- Telegram bot token + chat ID

Related API endpoints:

- `GET /api/alerts/status` — authenticated alert provider status; does not expose secret values
- `POST /api/alerts/test` — admin-only test alert send

Alert integrations fail safely when not configured. Provider status returns only safe booleans/metadata, never raw secrets.

## Docker

```bash
touch honeypot.db honeypot.log honeypot_out.log
docker-compose up --build
```

### Run with Security Ecosystem Tools

This profile adds Autoheal, Elastic Stack, Elasticvue, CyberChef, SpiderFoot, and Suricata:

```bash
docker-compose --profile ecosystem up --build
```

Service URLs:

- Honeypot Dashboard: `http://localhost:5050`
- Kibana: `http://localhost:5601`
- Elasticsearch: `http://localhost:9200`
- Elasticvue: `http://localhost:8088`
- CyberChef: `http://localhost:8089`
- SpiderFoot: `http://localhost:5001`

## Authentication Flows

### Bootstrap admin

The recommended path is to run `python setup.py` before starting the app. On startup, the app can bootstrap the admin account from `HONEYPOT_ADMIN_USER` and `HONEYPOT_ADMIN_PASS` when no user exists.

Manual bootstrap example:

```bash
curl -X POST http://localhost:5050/api/auth/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"username":"operator","password":"StrongPassword123"}'
```

### Login for Bearer token

```bash
curl -X POST http://localhost:5050/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"operator","password":"StrongPassword123"}'
```

Use returned token:

```bash
curl http://localhost:5050/api/auth/me \
  -H "Authorization: Bearer <token>"
```

### Create API key (admin)

```bash
curl -X POST http://localhost:5050/api/keys \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"name":"siem-ingest","role":"viewer"}'
```

Use API key:

```bash
curl http://localhost:5050/api/stats \
  -H "X-API-Key: <api_key>"
```

## API Endpoints

### Public/read endpoints

- `GET /api/meta`
- `GET /api/health`
- `GET /api/stats`
- `GET /api/connections?limit=100`
- `GET /api/commands?limit=100`
- `GET /api/attacks`
- `GET /api/services`

### Auth endpoints

- `POST /api/auth/bootstrap`
- `POST /api/auth/login`
- `GET /api/auth/me` (Bearer/API key)

### Alert endpoints

- `GET /api/alerts/status` (authenticated)
- `POST /api/alerts/test` (admin)

### Admin endpoints

- `POST /api/services/<name>/toggle`
- `GET /api/audit?limit=100`
- `GET /api/users`
- `POST /api/users`
- `POST /api/users/<username>/password`
- `DELETE /api/users/<username>`
- `GET /api/keys`
- `POST /api/keys`
- `POST /api/keys/<id>/revoke`

## Testing

Run the unittest suite from the project virtual environment:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

Run syntax/bytecode compile checks:

```bash
.venv/bin/python -m compileall -q setup.py env_loader.py api.py honeypot.py notifications.py main.py tests
```

## Added Tooling (v3 Ecosystem)

- **Autoheal**: automatically restarts unhealthy containers (`autoheal=true` label)
- **CyberChef**: web utility for encryption/encoding/compression/data transforms
- **Elastic Stack**: Logstash ingests `honeypot.log`, stores events in Elasticsearch, visualized in Kibana
- **Elasticvue**: lightweight Elasticsearch browser
- **fATT-style extractor**: `tools/fatt_extract.py` with `pyshark` for packet metadata/fingerprint summaries
- **SpiderFoot**: OSINT automation workspace
- **Suricata**: network security monitoring engine (host network mode)

## p0f and T-Pot Attack Map

Some tools are distribution-specific or better run externally:

- **p0f**: install on host and point at traffic mirror/SPAN interface for passive fingerprinting
- **T-Pot-Attack-Map**: typically tied to T-Pot’s own stack; integrate by forwarding your honeypot events into a compatible T-Pot/ELK pipeline

If you want, a dedicated `docker-compose.tpot-compat.yml` can be added later for a direct bridge.

## Data Model (high level)

- `connections`: inbound sessions and geolocation
- `commands`: captured command payloads and attack category
- `users`: local auth users (`admin`/`viewer`)
- `api_keys`: hashed API keys with role and status
- `audit_logs`: security-sensitive action trail

## Security Notes

- Run `python setup.py` before first use and choose a strong admin password
- Keep `.env`, `honeypot.db`, and logs out of git
- Keep the dashboard/API private by default; prefer `127.0.0.1`, VPN, reverse proxy auth, and TLS
- Restrict management endpoints behind firewall/IP allowlists
- Rotate admin passwords, API keys, webhook URLs, and bot tokens regularly
- Treat captured commands, credentials, headers, and payloads as hostile input
- Use production-grade log rotation and backup policies before public deployment

## Recommended Publish Checklist

- [ ] Run `python setup.py` and generate a local `.env`
- [ ] Replace demo credentials and secrets with strong values
- [ ] Keep dashboard/API behind VPN, firewall, or reverse proxy auth
- [ ] Enable HTTPS via Nginx/Caddy or another reverse proxy
- [ ] Configure alert providers only through environment variables
- [ ] Add regular DB backup and log rotation jobs
- [ ] Run the full unittest suite before deployment
- [ ] Review `.env.example` and deployment docs for placeholders only

## Demo Traffic Script

To simulate local lab traffic against your own honeypot:

```bash
python3 hardcore_stress.py
```
