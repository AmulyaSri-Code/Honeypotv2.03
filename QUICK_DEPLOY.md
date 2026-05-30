# HoneyPot v3 Quick Deploy

This is the fastest safe path for a new user.

## Option A: Docker, recommended

```bash
./scripts/quick_deploy.sh docker
```

Then open:

```text
http://localhost:5050
```

The script creates:

- `.env` with generated secrets and safe defaults
- `.deploy-credentials.txt` with the generated dashboard login
- Docker volumes for persistent database/log storage

Useful commands:

```bash
./scripts/quick_deploy.sh status
make logs
make stop
```

## Option B: Local Python

```bash
./scripts/quick_deploy.sh local
.venv/bin/python main.py
```

Then open:

```text
http://localhost:5050
```

## Public server deployment

On a VPS or server with Docker installed:

```bash
git clone <your-repo-url> honeypot-v3
cd honeypot-v3
HONEYPOT_PUBLIC_URL=https://your-domain.example ./scripts/quick_deploy.sh docker
```

Default Docker behavior:

- Honeypot sensors are exposed on ports `2222`, `2121`, `8080`, `2323`, and `4444`.
- The dashboard/API is bound to `127.0.0.1:5050` for safety.
- Put Nginx, Caddy, Tailscale, Cloudflare Tunnel, or a VPN in front of the dashboard instead of exposing it directly.

## Reverse proxy example with Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name honeypot.example.com;

    # Put real TLS config here.

    location / {
        proxy_pass http://127.0.0.1:5050;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Trap-path sidecar example

For an existing website, route only suspicious paths to the honeypot HTTP sensor:

```nginx
location ~* ^/(\.env|\.git|wp-login\.php|wp-admin|phpmyadmin|adminer|cgi-bin|server-status|manager/html) {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

Keep normal website traffic going to the real application.

## Enable fast indexing after deployment

Set your public URL before deploying:

```bash
HONEYPOT_PUBLIC_URL=https://your-domain.example ./scripts/quick_deploy.sh docker
```

Then submit:

```bash
python scripts/ping_indexing.py --base-url https://your-domain.example --key "$HONEYPOT_INDEXNOW_KEY"
```

Also submit `/sitemap.xml` in Google Search Console and Bing Webmaster Tools.

## Security checklist

- Save `.deploy-credentials.txt` in a password manager, then delete it.
- Never commit `.env` or `.deploy-credentials.txt`.
- Keep dashboard/API private behind TLS, VPN, or SSO.
- Confirm health:

```bash
curl http://127.0.0.1:5050/api/health
```

- Watch logs:

```bash
docker compose logs -f honeypot
```
