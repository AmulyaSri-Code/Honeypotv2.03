# Honeypot Website Deployment Guide

This project should be deployed as an isolated honeypot, not as a normal trusted web app. Assume every exposed listener receives hostile traffic.

## Recommended deployment model

1. Use a dedicated VPS or cloud VM that contains no personal files and has no route into private networks.
2. Run the honeypot in Docker or a VM as a non-root workload.
3. Expose decoy ports publicly only if the provider firewall allows you to restrict and monitor them.
4. Keep the dashboard private by default:
   - bind dashboard port 5050 to localhost, or
   - protect it with VPN, Cloudflare Access, Tailscale, or reverse-proxy authentication.
5. Forward logs to a separate SIEM/storage account if you expect real attacker traffic.

## Files added for deployment

- `.env.example` — safe template for required runtime secrets.
- `docker-compose.production.yml` — hardened compose profile with localhost-only dashboard binding.

## Basic VPS deployment

```bash
git clone <your-repo-url> honeypot
cd honeypot
cp .env.example .env
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
# Put that output into HONEYPOT_AUTH_SECRET in .env.
# Replace HONEYPOT_ADMIN_PASS with a long unique password.

touch honeypot.db honeypot.log honeypot_out.log
docker compose -f docker-compose.production.yml up -d --build
```

## Reverse proxy pattern

Recommended public shape:

- Public decoy services:
  - `2222/tcp`, `2121/tcp`, `8080/tcp`, `2323/tcp`, `4444/tcp`
- Private management:
  - `5050/tcp` bound to localhost only
- HTTPS dashboard:
  - Caddy/Nginx on `443/tcp`
  - protected by VPN, basic auth, mTLS, or identity-aware proxy

Example Caddy route for a private dashboard:

```caddyfile
honeypot.example.com {
  encode zstd gzip
  basicauth /* {
    admin <hashed-password-from-caddy-hash-password>
  }
  reverse_proxy 127.0.0.1:5050
  header {
    X-Content-Type-Options nosniff
    X-Frame-Options DENY
    Referrer-Policy no-referrer
  }
}
```

## Cloud options

Good options:

- DigitalOcean Droplet
- Hetzner Cloud VM
- AWS EC2
- Azure VM
- GCP Compute Engine
- Fly.io/Render/Railway only for dashboard demos, not raw TCP honeypot listeners

For a full honeypot with SSH/FTP/Telnet/NC decoy ports, use a VM provider that supports arbitrary inbound TCP ports.

## Safety checklist before internet exposure

- [ ] `.env` exists and does not contain defaults.
- [ ] `HONEYPOT_AUTH_SECRET` is a long random value.
- [ ] `HONEYPOT_ADMIN_PASS` is unique and long.
- [ ] Dashboard is not directly exposed without authentication.
- [ ] Host firewall only allows intended ports.
- [ ] Outbound traffic is restricted where possible.
- [ ] VM is dedicated and isolated from private networks.
- [ ] Logs and database are backed up or exported to separate storage.
- [ ] Resource limits and monitoring are enabled.
- [ ] You have authorization to run the honeypot on the chosen network.

## Local production run

```bash
cp .env.example .env
# edit .env first
touch honeypot.db honeypot.log honeypot_out.log
docker compose -f docker-compose.production.yml up --build
```

Then open the dashboard through the local binding:

```text
http://127.0.0.1:5050
```
