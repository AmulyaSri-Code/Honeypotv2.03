# Honeypot Upgrade Roadmap

## Goal
Build a production-ready defensive honeypot platform that safely attracts, observes, classifies, and reports hostile activity while keeping the host and management plane isolated.

## Phase 1: Dashboard Command Center — started

Implemented:

- Threat Command Center panel with calculated risk score.
- Deployment readiness checks for secret hygiene, admin password defaults, and dashboard binding posture.
- Top Attackers panel.
- New `/api/threats/summary` endpoint for operational intelligence.
- Tests for the new threat summary API.
- Deployment documentation and production compose baseline.

Next improvements:

- Add timeline chart from `/api/threats/summary.timeline`.
- Add top countries and service mix widgets.
- Add full-screen incident detail drawer for each command/session.
- Add filters by service, severity, IP, country, and time window.
- Add export buttons for JSON/CSV/IOC reports.

## Phase 2: Safety and deployment hardening

- Require non-default `HONEYPOT_AUTH_SECRET` and `HONEYPOT_ADMIN_PASS` in production mode.
- Move SQLite/log paths to configurable `HONEYPOT_DATA_DIR`.
- Add structured JSON logs.
- Add log rotation.
- Add Docker resource limits.
- Add read-only root filesystem where possible.
- Add egress firewall guidance/scripts.
- Keep dashboard private behind reverse proxy/VPN/identity-aware access.

## Phase 3: Better attacker/session intelligence

- Session table with start/end/duration, commands, credentials attempted, user agents, headers, and raw payload snippets.
- IOC extraction for URLs, domains, hashes, IPs, filenames, and suspicious paths.
- Payload normalization and safe truncation.
- MITRE ATT&CK-style technique tagging for common activity.
- Brute-force detector by source IP and username/password patterns.
- Scanner/fingerprint detector for Nmap, masscan, curl, wget, botnets, and exploit probes.

## Phase 4: More decoys

- Fake admin login portals.
- Fake REST API with vulnerable-looking endpoints that only log.
- Fake database banners for Redis/MySQL/Postgres without real data.
- Fake IoT camera/router web UI.
- Fake cloud metadata endpoint decoy in isolated mode.
- Fake S3/minio-style bucket listing decoy.

## Phase 5: Alerting and reporting

- Webhook alerts for critical events.
- Slack/Discord/Telegram alert integrations.
- Daily digest report.
- CSV/JSON export.
- STIX/TAXII-compatible IOC export later if needed.

## Phase 6: Cloud deployment patterns

Preferred for real honeypot exposure:

- Dedicated VPS/VM: DigitalOcean, Hetzner, AWS EC2, Azure VM, GCP Compute Engine.
- Dashboard protected with Cloudflare Access, Tailscale, VPN, mTLS, or reverse proxy auth.
- Raw honeypot TCP ports exposed through cloud firewall only where intended.

Not ideal for full honeypot exposure:

- Render/Fly/Railway/Vercel/Netlify, because they are mainly HTTP app platforms and do not reliably expose arbitrary TCP decoy services.

## Security principles

- Never run this on a personal machine exposed to the internet.
- Never connect the honeypot to private/home networks.
- Treat logs and captured payloads as hostile.
- Keep management endpoints private.
- Restrict outbound traffic where possible.
- Use a dedicated low-privilege runtime user.
