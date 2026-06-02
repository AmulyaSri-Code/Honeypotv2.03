# HoneyPot v3 Hardened Production Deployment

HoneyPot v3 is defensive monitoring software. Deploy it only on infrastructure you own or are authorized to monitor. Treat captured payloads and credentials as hostile data.

## Recommended topology

```text
Internet
  -> firewall / load balancer / reverse proxy
      -> exposed honeypot sensor ports on a controlled interface
      -> private dashboard/API on 127.0.0.1, VPN, or admin-only reverse-proxy path
      -> optional n8n automation on 127.0.0.1 or an internal Docker network
```

Do not expose the dashboard/API directly to the public internet without TLS, strong authentication, rate limiting, and network access controls.

## Host baseline

- Run on a dedicated VM/container host, not on your primary workstation.
- Use a non-root service account where possible.
- Patch the OS and container runtime before exposure.
- Restrict inbound firewall rules to intentional sensor ports and private admin access.
- Put outbound webhook destinations on an allowlist if your environment supports egress filtering.
- Configure log rotation and retention for `honeypot.log`, `honeypot.db`, and exported reports.

## Secrets and configuration

Generate local configuration:

```bash
python setup.py --non-interactive \
  --admin-user operator \
  --admin-pass 'replace-with-a-long-random-password' \
  --bind-host 127.0.0.1 \
  --sensor-bind-host 0.0.0.0 \
  --dashboard-port 5050
```

Required production settings:

```bash
HONEYPOT_ADMIN_USER=operator
HONEYPOT_ADMIN_PASS=long_unique_password
HONEYPOT_AUTH_SECRET=long_random_token_urlsafe_secret
HONEYPOT_BIND_HOST=127.0.0.1
HONEYPOT_SENSOR_BIND_HOST=0.0.0.0
HONEYPOT_TRUSTED_PROXIES=127.0.0.1
HONEYPOT_ALLOW_DEFAULT_ADMIN=false
HONEYPOT_COOKIE_SECURE=true
HONEYPOT_RATE_LIMIT_PER_MIN=240
HONEYPOT_ENRICHMENT_ENABLED=true
HONEYPOT_ENRICHMENT_PROVIDER=ip-api
```

Keep `.env`, webhook URLs, bot tokens, API keys, database files, and captured logs out of git. The dashboard root redirects to `/login` unless the browser has a valid HttpOnly `honeypot_session` cookie; keep the dashboard endpoint private even with app-level auth enabled.

## Reverse proxy example

Nginx dashboard proxy with TLS and private access controls:

```nginx
server {
  listen 443 ssl http2;
  server_name honeypot-admin.example.com;

  ssl_certificate /etc/letsencrypt/live/honeypot-admin.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/honeypot-admin.example.com/privkey.pem;

  allow 203.0.113.10;
  deny all;

  location / {
    proxy_pass http://127.0.0.1:5050;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

If the proxy is trusted, include its IP in `HONEYPOT_TRUSTED_PROXIES` so the API uses the original client IP safely.

## Docker deployment

Use the committed compose file for the application. It binds the dashboard to host loopback (`127.0.0.1:5050`) while allowing sensor ports through Docker, and keeps n8n private:

```bash
cp .env.example .env
python setup.py

docker compose up --build -d honeypot

scripts/setup_n8n.sh
```

Production recommendations:

- Bind dashboard/API to loopback or an internal Docker network when possible.
- Put n8n behind VPN/reverse-proxy auth; the compose profile binds it to `127.0.0.1:5678` by default.
- Use Docker secrets or your platform secret manager for real webhook URLs and credentials.
- Persist `honeypot.db`, `honeypot.log`, and `n8n_data` on backed-up storage.

## IP reputation and ASN enrichment

HoneyPot v3 enriches connection records with:

- ASN and ASN organization
- provider name
- reputation score and level
- reputation flags such as `hosting_provider`, `proxy_or_vpn`, or `infrastructure_asn`

Private, loopback, and reserved IPs are handled locally and do not trigger external lookups. Disable external enrichment with:

```bash
HONEYPOT_ENRICHMENT_ENABLED=false
```

## Case-management workflow

Use the API to create and update cases from dashboard triage, n8n, or external ticketing tools.

```bash
curl -X POST http://localhost:5050/api/cases \
  -H 'X-API-Key: hpv3_example_key' \
  -H 'Content-Type: application/json' \
  -d '{"title":"Investigate repeated SSH brute force","severity":"high","source_ip":"203.0.113.44","assignee":"soc-1"}'
```

Supported statuses: `open`, `investigating`, `contained`, `closed`.

## n8n daily/weekly reports

Import these workflow templates:

- `n8n-workflows/honeypot-v3-critical-alert.json`
- `n8n-workflows/honeypot-v3-daily-weekly-reports.json`

The alert workflow is imported and smoke-tested by:

```bash
scripts/setup_n8n.sh
```

The report workflow is designed to call:

- `GET /api/reports/daily`
- `GET /api/reports/weekly`

Use a viewer API key in n8n via the `X-API-Key` header. Do not paste real keys into workflow JSON committed to git.

## Verification before go-live

Run:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m compileall -q setup.py env_loader.py enrichment.py api.py honeypot.py notifications.py main.py test_services.py tests
.venv/bin/python -m json.tool n8n-workflows/honeypot-v3-critical-alert.json >/dev/null
.venv/bin/python -m json.tool n8n-workflows/honeypot-v3-daily-weekly-reports.json >/dev/null
docker compose config >/dev/null
```

Then perform a controlled sensor smoke test from an allowed network and confirm dashboard telemetry, case creation, reports, and n8n webhook delivery.
