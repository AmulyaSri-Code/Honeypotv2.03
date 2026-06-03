# HoneyPot v3 Go-Live Checklist

Use this checklist before exposing HoneyPot sensors to the internet or routing traffic from an existing website.

## Authorization

- [ ] I own this website/server or am explicitly authorized to monitor it.
- [ ] I understand captured payloads and credentials must be handled as hostile data.

## Preflight

- [ ] `.env` exists and is not committed.
- [ ] `.deploy-credentials.txt` was saved in a password manager and deleted.
- [ ] Dashboard/API remains private on loopback, VPN, Tailscale, Cloudflare Access, or protected reverse proxy.
- [ ] `HONEYPOT_AUTH_SECRET` is strong and not default.
- [ ] Admin password is strong and not default.
- [ ] `HONEYPOT_ALLOW_DEFAULT_ADMIN=false`.
- [ ] `HONEYPOT_COOKIE_SECURE=true` when the dashboard is served through HTTPS.
- [ ] `HONEYPOT_TRUSTED_PROXIES` includes only trusted proxy IPs.
- [ ] Cloud firewall/security group exposes only intentional sensor ports.
- [ ] Docker Compose config validates.
- [ ] `make doctor` passes, or `./scripts/doctor.sh --offline` passes before the dashboard is started.
- [ ] `/api/health` returns HTTP 200.
- [ ] Authenticated `/api/setup/status` returns safe readiness booleans without exposing secrets.
- [ ] Logs rotate and disk usage is monitored.
- [ ] Backups are configured for database, logs, and `.env`.
- [ ] Alerts are either disabled intentionally or tested successfully.

Recommended commands:

```bash
bash -n scripts/quick_deploy.sh scripts/doctor.sh docker-entrypoint.sh
./scripts/doctor.sh --offline
make doctor
docker compose config >/tmp/honeypot-compose.yml
docker compose -f docker-compose.production.yml config >/tmp/honeypot-production-compose.yml
curl -i http://127.0.0.1:5050/api/health
```

## Website sidecar checks

- [ ] Normal homepage goes to the real website backend.
- [ ] Real login/customer/admin routes still go to the real website backend.
- [ ] Only suspicious trap paths route to the HoneyPot HTTP sensor.
- [ ] `/.env` test request appears in the HoneyPot dashboard.
- [ ] `/wp-login.php` test request appears in the HoneyPot dashboard only if the real site does not use that path.
- [ ] Reverse proxy passes `X-Real-IP` and `X-Forwarded-For`.
- [ ] Real users are not routed to the honeypot.

## Public decoy VPS checks

- [ ] Exposed sensor ports are intentional.
- [ ] Dashboard port `5050` is not directly public.
- [ ] Admin access uses VPN, Tailscale, Cloudflare Access, SSH tunnel, SSO, or IP allowlist.
- [ ] Host firewall rules are documented.
- [ ] Restart behavior after reboot is verified.

## Post-live

- [ ] Watch logs for the first 15 minutes.
- [ ] Confirm dashboard telemetry updates.
- [ ] Confirm alert delivery if enabled.
- [ ] Confirm disk usage remains bounded.
- [ ] Confirm backup job or manual backup path works.
- [ ] Record deployment notes for future upgrades/rollback.
