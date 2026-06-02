# HoneyPot v3 Website Backend Integration Guide

This guide shows how to attach HoneyPot v3 to the backend of an existing website so a site owner can capture suspicious traffic without rewriting their app.

Use this only on websites, servers, and infrastructure you own or are explicitly authorized to monitor. Treat all captured payloads as hostile data.

## Recommended Pattern

Run HoneyPot v3 as a private sidecar service beside your real website backend.

```text
Internet
  |
  v
Reverse proxy / load balancer
  |
  |-- normal app traffic --------------> real website backend
  |
  |-- suspicious trap paths -----------> HoneyPot v3 HTTP sensor
  |
  |-- private dashboard/API -----------> HoneyPot v3 dashboard, admin-only
```

Why this pattern works:

- Your real website stays in control of normal users.
- HoneyPot v3 only receives suspicious routes you intentionally route to it.
- The dashboard can stay private on `127.0.0.1`, VPN, or an internal network.
- n8n/Slack/Discord/Telegram alerts remain optional.

## What to Route to HoneyPot v3

Good trap candidates are paths that real users should not need:

```text
/wp-admin
/wp-login.php
/phpmyadmin
/adminer
/.env
/.git
/vendor
/cgi-bin
/server-status
/boaform/admin/formLogin
/manager/html
```

Do not proxy your entire real website to the honeypot unless the site is intentionally a lab/decoy.

## Quick Setup

### 1. Install HoneyPot v3 next to your website backend

```bash
git clone https://github.com/AmulyaSri-Code/Honeypotv2.03.git
cd Honeypotv2.03
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 2. Create a safe local configuration

For a website sidecar, keep the dashboard and sensors private unless you intentionally expose them through a reverse proxy.

```bash
python setup.py --non-interactive \
  --admin-user operator \
  --admin-pass 'replace_with_a_strong_password' \
  --bind-host 127.0.0.1 \
  --sensor-bind-host 127.0.0.1 \
  --dashboard-port 5050
```

If your reverse proxy runs in a different container, use the Docker service name or private container network instead of public exposure. Keep `/login` and `/` for the dashboard behind VPN, IP allowlisting, or your admin-only reverse-proxy route; never route those dashboard paths to normal public visitors.

### 3. Start HoneyPot v3

```bash
source .venv/bin/activate
python main.py
```

Private local endpoints:

```text
Dashboard/API: http://127.0.0.1:5050
HTTP sensor:   http://127.0.0.1:8080
```

### 4. Route only trap paths from your website to the HTTP sensor

Use one of the reverse-proxy examples below.

## Nginx Example

This routes normal traffic to your real app and suspicious paths to HoneyPot v3.

```nginx
upstream website_backend {
    server 127.0.0.1:3000;
}

upstream honeypot_http_sensor {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name example.com;

    # Normal website traffic
    location / {
        proxy_pass http://website_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Suspicious trap routes
    location ~* ^/(wp-admin|wp-login\.php|phpmyadmin|adminer|cgi-bin|manager/html|server-status|boaform/admin/formLogin)(/.*)?$ {
        proxy_pass http://honeypot_http_sensor;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Sensitive-file probes
    location ~* ^/(\.env|\.git|vendor)(/.*)?$ {
        proxy_pass http://honeypot_http_sensor;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Caddy Example

```caddyfile
example.com {
    @traps path /wp-admin* /wp-login.php /phpmyadmin* /adminer* /.env /.git* /vendor* /cgi-bin* /server-status /manager/html* /boaform/admin/formLogin*
    reverse_proxy @traps 127.0.0.1:8080

    reverse_proxy 127.0.0.1:3000
}
```

## Node.js / Express Backend Example

Use this when your Node backend directly handles routing and you do not want to edit the edge proxy.

Install proxy middleware:

```bash
npm install http-proxy-middleware
```

Add trap routing before your normal app routes:

```js
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();

const trapPattern = /^\/(wp-admin|wp-login\.php|phpmyadmin|adminer|cgi-bin|manager\/html|server-status|boaform\/admin\/formLogin|\.env|\.git|vendor)(\/.*)?$/i;

app.use((req, res, next) => {
  if (trapPattern.test(req.path)) {
    return createProxyMiddleware({
      target: 'http://127.0.0.1:8080',
      changeOrigin: true,
      xfwd: true,
    })(req, res, next);
  }
  return next();
});

// Normal website routes continue below.
app.get('/', (req, res) => res.send('real website'));

app.listen(3000);
```

## Python / Django or Flask Backend Pattern

For Python web apps, prefer Nginx/Caddy in front. If you must proxy from app code, keep the trap route narrow and forward headers carefully.

Flask-style sketch:

```python
import requests
from flask import Flask, request, Response

app = Flask(__name__)
HONEYPOT_HTTP_SENSOR = "http://127.0.0.1:8080"
TRAP_PREFIXES = (
    "/wp-admin",
    "/wp-login.php",
    "/phpmyadmin",
    "/adminer",
    "/.env",
    "/.git",
    "/vendor",
    "/cgi-bin",
    "/server-status",
    "/manager/html",
)

@app.before_request
def route_traps_to_honeypot():
    if not request.path.lower().startswith(TRAP_PREFIXES):
        return None

    upstream = requests.request(
        method=request.method,
        url=f"{HONEYPOT_HTTP_SENSOR}{request.full_path}",
        headers={
            "Host": request.host,
            "X-Real-IP": request.remote_addr or "",
            "X-Forwarded-For": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
            "X-Forwarded-Proto": request.scheme,
            "User-Agent": request.headers.get("User-Agent", ""),
        },
        data=request.get_data(),
        timeout=5,
    )
    return Response(upstream.content, status=upstream.status_code, headers=dict(upstream.headers))
```

## Docker Compose Sidecar Example

If your website already uses Docker Compose, add HoneyPot v3 as a private service and route trap paths from your proxy container.

```yaml
services:
  website:
    build: ./website
    expose:
      - "3000"

  honeypot:
    build: ./Honeypotv2.03
    env_file:
      - ./Honeypotv2.03/.env
    expose:
      - "5050"
      - "8080"
    environment:
      HONEYPOT_BIND_HOST: 0.0.0.0
      HONEYPOT_SENSOR_BIND_HOST: 0.0.0.0
      HONEYPOT_DASHBOARD_PORT: 5050
      HONEYPOT_ALLOW_DEFAULT_ADMIN: "false"

  proxy:
    image: nginx:alpine
    ports:
      - "443:443"
    depends_on:
      - website
      - honeypot
```

Inside the proxy container, route traps to:

```text
http://honeypot:8080
```

Keep the dashboard private. If you expose it, protect it with VPN, SSO, IP allowlisting, or reverse-proxy authentication.

## Optional Alerts for Website Owners

Enable alerts only when you have a destination configured.

```bash
HONEYPOT_ALERTS_ENABLED=true
HONEYPOT_ALERT_MIN_SEVERITY=high
```

For n8n automation:

```bash
N8N_WEBHOOK_URL=http://n8n:5678/webhook/honeypot-v3-alert
```

Use n8n to enrich attacker IPs, create tickets, notify analysts, or generate daily reports. Do not paste real webhook URLs or bot tokens into public docs, issues, commits, or chat logs.

## Backend Integration Checklist

Before going live:

- [ ] HoneyPot v3 is installed outside your public web root.
- [ ] `.env` is not committed to git.
- [ ] Dashboard/API is private or protected with strong authentication.
- [ ] Only suspicious trap routes are proxied to the honeypot.
- [ ] Real customer/user routes still go to the real website backend.
- [ ] `X-Real-IP` and `X-Forwarded-For` are passed to HoneyPot v3.
- [ ] Alerts are tested with non-secret placeholders first.
- [ ] Logs and captured payloads are stored securely.
- [ ] Legal/consent requirements for your environment are reviewed.

## Simple Integration Test

After routing trap paths, test from a separate terminal:

```bash
curl -i https://example.com/.env
curl -i https://example.com/wp-login.php
curl -i https://example.com/phpmyadmin
```

Then check the HoneyPot v3 dashboard or API for captured activity.

Use your real domain in place of `example.com`. Do not run tests against websites you do not own.
