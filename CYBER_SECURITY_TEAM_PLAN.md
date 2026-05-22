# Cyber Security Expert & Developer Team

Project: `/Users/amulyasrivastava/Desktop/Honeypotv2.03`
Mission: Upgrade Honeypotv2.03 into a safer, more production-ready defensive honeypot platform.

## Safety Boundary

This team works on legal, authorized defensive security only:

- Honeypot development
- Secure coding
- Bug finding and bug fixing
- Defensive testing
- Threat intelligence and telemetry
- Logging, alerting, dashboards, and reporting
- Deployment hardening and isolation

This team does not build or support illegal activity, unauthorized access, malware, credential theft, destructive operations, or real-world exploitation of third-party systems.

## Team Members and Work Split

### 1. Captain Shield — Security Architect / Scope Lead

Owns:
- Legal/authorized scope enforcement
- Threat model
- Production safety gates
- Management-plane isolation
- Risk prioritization

Current priority tasks:
- Remove or gate legacy Basic auth fallback.
- Require non-default secrets in production mode.
- Keep dashboard/API management private.
- Ensure only safe defensive features are added.

### 2. ByteForge — Backend/API Developer

Owns:
- Flask API
- Authentication and authorization
- SQLite schema and migrations
- API input validation
- Tests for API behavior

Current priority tasks:
- Require auth for sensitive telemetry endpoints.
- Clamp all `limit` query parameters with lower and upper bounds.
- Add isolated test DB fixtures.
- Add tests for auth boundaries, default secret checks, and bad input.

### 3. HoneyRanger — Honeypot Services Engineer

Owns:
- SSH, FTP, HTTP, Telnet, and NC decoy services
- Session handling
- Safe attacker interaction capture
- Resource limits and service lifecycle

Current priority tasks:
- Add per-service and per-IP connection caps.
- Reduce thread/resource exhaustion risk.
- Add bounded payload capture and safe truncation.
- Improve fake-shell line buffering and session realism.
- Persist decoy SSH host key.

### 4. SignalSage — Threat Intelligence / Detection Engineer

Owns:
- IOC extraction
- Attack classification
- Scanner/fingerprint detection
- Risk scoring
- Reporting and export formats

Current priority tasks:
- Extract URLs, domains, IPs, hashes, filenames, and suspicious paths from commands.
- Add time-windowed risk summaries.
- Add MITRE-style tags for common behavior.
- Add JSON/CSV/IOC export for defensive analysis.

### 5. OpsFort — DevSecOps / Deployment Engineer

Owns:
- Docker and Compose hardening
- Deployment documentation
- Secrets and environment configuration
- Logging/rotation/resource limits
- CI safety checks

Current priority tasks:
- Add production resource limits and Docker log rotation.
- Make filesystem read-only where possible.
- Pin Docker images or document update policy.
- Add deployment preflight checklist.
- Add firewall and egress-control guidance.

## Immediate Findings From Inspection

### Critical / P0

1. Admin Basic fallback risk
- File: `api.py`
- Issue: admin routes allow legacy Basic auth fallback with default `admin/secret` if `DASHBOARD_USER` and `DASHBOARD_PASS` are not set.
- Fix: remove Basic fallback or require explicit opt-in and fail closed on defaults.

2. Sensitive telemetry endpoints are public
- File: `api.py`
- Endpoints: `/api/connections`, `/api/commands`, `/api/attacks`, `/api/stats`, `/api/threats/summary`, `/api/services`
- Issue: captured IPs, commands, credentials/payload-like strings, geolocation, and threat summaries can be read without auth.
- Fix: require viewer/admin auth for all telemetry except minimal `/api/health` and `/api/meta`.

3. Default auth secret exists
- File: `security.py`
- Issue: `HONEYPOT_AUTH_SECRET` defaults to `change-me-in-production`.
- Fix: production mode should refuse startup when secret is missing/default.

4. Thread-per-connection exhaustion risk
- File: `honeypot.py`
- Issue: each connection creates a daemon thread with no hard global/service/per-IP cap.
- Fix: add bounded worker pool/semaphore, per-IP limits, shorter timeouts, and backpressure.

### High / P1

5. Negative limit values can bypass caps
- File: `api.py`
- Issue: `LIMIT -1` can return all rows.
- Fix: use `max(1, min(parsed_limit, 500))` with safe parsing.

6. `X-Forwarded-For` is trusted unconditionally
- File: `api.py`
- Issue: clients can spoof rate-limit/audit IP unless behind trusted proxy.
- Fix: only trust forwarded headers from configured trusted proxies.

7. Captured credentials/commands need sensitive-data controls
- File: `honeypot.py`
- Issue: raw attempted credentials and commands may be stored/logged.
- Fix: add redaction/hash mode, retention policy, access controls, and warnings.

8. Log injection risk
- File: `honeypot.py`
- Issue: raw attacker input can include newlines/control characters and poison logs.
- Fix: structured JSON logs, escaping, truncation, and log rotation.

9. Dashboard auth flow is incomplete
- File: `dashboard/index.html`
- Issue: service toggle calls protected API without bearer token flow.
- Fix: add login UI, token storage for session, authenticated requests, and visible auth errors.

## First Sprint Plan

### Sprint Goal
Make the honeypot safer before adding more decoy features.

### Task 1 — API Auth Hardening
Owner: ByteForge + Captain Shield

- Remove or gate Basic fallback.
- Require viewer/admin auth for sensitive telemetry endpoints.
- Keep `/api/health`, `/api/meta`, and static dashboard loading public only if necessary.
- Add tests for unauthorized vs authorized access.

### Task 2 — Input and Rate-Limit Safety
Owner: ByteForge

- Add safe `parse_limit()` helper.
- Clamp `limit` to `1..500`.
- Add tests for negative, zero, non-integer, and oversized values.
- Add trusted proxy handling before trusting `X-Forwarded-For`.

### Task 3 — Honeypot Resource Protection
Owner: HoneyRanger

- Add per-service connection caps.
- Add per-IP cap or cooldown.
- Add bounded payload size.
- Add safe truncation for commands and HTTP requests.
- Add tests for truncation and service lifecycle helpers.

### Task 4 — Threat Intelligence Upgrade
Owner: SignalSage

- Add IOC extraction module.
- Extract URLs, domains, IPs, hashes, suspicious filenames, and paths.
- Add `/api/iocs` or include IOCs in threat summary.
- Add JSON/CSV export.

### Task 5 — Deployment Hardening
Owner: OpsFort

- Add Docker resource limits.
- Add logging max-size/max-file.
- Add production startup secret checks.
- Improve deployment docs with firewall and egress guidance.

## Test Commands

Known working test command in current project environment:

```bash
cd /Users/amulyasrivastava/Desktop/Honeypotv2.03
PYTHONPATH=. ./.venv/bin/python tests/test_threat_summary_api.py
```

Current result observed:

```text
Ran 2 tests in 0.010s
OK
```

`pytest` is not installed in the current Python environments, so use unittest or install pytest before switching test runner.

## Current Git State Warning

Before making large edits, review existing uncommitted changes:

```bash
git status --short
git diff --stat
```

Observed uncommitted paths during inspection:

- Modified: `Dockerfile`, `api.py`, `dashboard/index.html`, `honeypot.db`, `main.py`
- Untracked: `.env.example`, `DEPLOYMENT.md`, `UPGRADE_ROADMAP.md`, `docker-compose.production.yml`, `tests/`

Do not overwrite user changes. Prefer small patches and verify with tests after every change.
