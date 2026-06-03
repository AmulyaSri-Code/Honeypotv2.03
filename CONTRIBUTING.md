# Contributing to HoneyPot v3

HoneyPot v3 is defensive monitoring software for systems you own or are explicitly authorized to monitor. Contributions must preserve that safety boundary.

## Safety rules

- Do not add offensive exploitation features or instructions for unauthorized use.
- Treat captured payloads, credentials, logs, and database records as hostile data.
- Do not commit `.env`, webhook URLs, API keys, database files, logs, reports, local credentials, caches, or generated temporary files.
- Keep dashboard/API management surfaces private by default.
- Keep integrations such as n8n, Slack, Discord, Telegram, SMTP, and enrichment providers optional.

## Current roadmap gaps

HoneyPot v3 intentionally documents missing protocol areas so operators do not mistake them for silent coverage:

- RDP sensor support is a roadmap item, not a currently supported production sensor.
- SMB sensor support is a roadmap item, not a currently supported production sensor.
- Add these only with defensive/authorized lab use, safe logging, rate limits, tests, and clear deployment warnings.

## Development workflow

1. Create or update tests before behavior changes when practical.
2. Run targeted tests for changed areas.
3. Run the full verification suite before release or pull request.
4. Keep runtime artifacts out of git and Docker build context.

Recommended local verification:

```bash
python3 -m compileall -q api.py main.py honeypot.py security.py notifications.py setup.py ml tests
bash -n scripts/quick_deploy.sh docker-entrypoint.sh
docker compose config >/tmp/honeypot-compose.yml
docker compose -f docker-compose.production.yml config >/tmp/honeypot-production-compose.yml
pytest -q
```

If the project virtual environment exists, prefer:

```bash
.venv/bin/python -m pytest -q
```

## Setup and documentation expectations

User-facing setup material should include:

- exact commands;
- expected output or success signal;
- what stays private;
- what ports are exposed;
- how to verify health;
- how to recover from common failures.

Use `SETUP_CHOOSER.md`, `QUICK_DEPLOY.md`, `GO_LIVE_CHECKLIST.md`, and `TROUBLESHOOTING.md` as the operator-facing baseline.
