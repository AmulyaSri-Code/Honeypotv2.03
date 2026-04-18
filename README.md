# Honeypot v3.00 // Advanced Threat Intelligence Platform

Honeypot v3.00 is a multi-service deception platform that captures hostile traffic, classifies attack commands with ML, and exposes a hardened API/dashboard for operations and analysis.

## v3.00 Product Features

- Multi-service honeypot listeners: SSH (`2222`), FTP (`2121`), HTTP (`8080`), Telnet (`2323`), NC (`4444`)
- Flask API and realtime dashboard on `5050`
- ML command classification (TF-IDF + Random Forest via `scikit-learn`)
- SQLite with WAL mode for concurrent writes
- Token auth + API key auth + optional basic-auth fallback for legacy admin actions
- User management, API key lifecycle, audit logs, health checks
- Request throttling and secure response headers for safer public exposure

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

### 3) Configure environment (recommended)

```bash
export HONEYPOT_ADMIN_USER=admin
export HONEYPOT_ADMIN_PASS='change_this_now'
export HONEYPOT_AUTH_SECRET='super_long_random_secret'
export HONEYPOT_TOKEN_TTL_SECONDS=28800
export HONEYPOT_RATE_LIMIT_PER_MIN=240
```

### 4) Run

```bash
python3 main.py
```

Open `http://localhost:5050`.

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

### Bootstrap admin (only when no user exists)

```bash
curl -X POST http://localhost:5050/api/auth/bootstrap \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongPassword123"}'
```

### Login for Bearer token

```bash
curl -X POST http://localhost:5050/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"StrongPassword123"}'
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

If you want, I can add a dedicated `docker-compose.tpot-compat.yml` in the next step for a direct bridge.

## Data Model (high level)

- `connections`: inbound sessions and geolocation
- `commands`: captured command payloads and attack category
- `users`: local auth users (`admin`/`viewer`)
- `api_keys`: hashed API keys with role and status
- `audit_logs`: security-sensitive action trail

## Security Notes

- Change defaults before publishing (`HONEYPOT_ADMIN_PASS`, `HONEYPOT_AUTH_SECRET`)
- Keep `honeypot.db` and logs on secure storage
- Prefer reverse proxy + TLS in production
- Restrict management endpoints behind firewall/IP allowlist

## Recommended Publish Checklist

- [ ] Replace demo credentials and secrets
- [ ] Enable HTTPS via Nginx/Caddy
- [ ] Add regular DB backup job
- [ ] Add CI tests for auth and admin APIs
- [ ] Add monitoring/alerting for service health

## Demo Traffic Script

To simulate attack traffic:

```bash
python3 hardcore_stress.py
```
