#!/usr/bin/env bash
set -u

MODE="online"
if [[ "${1:-}" == "--offline" ]]; then
  MODE="offline"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
ENV_FILE="${HONEYPOT_ENV_FILE:-.env}"
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $1"; PASS_COUNT=$((PASS_COUNT + 1)); }
warn() { echo "WARN: $1"; WARN_COUNT=$((WARN_COUNT + 1)); }
fail() { echo "FAIL: $1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
have_cmd() { command -v "$1" >/dev/null 2>&1; }
load_env() {
  [[ -f "$ENV_FILE" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "${line// }" || "${line#\#}" != "$line" || "$line" != *=* ]] && continue
    key="${line%%=*}"
    value="${line#*=}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    if [[ -z "${!key+x}" ]]; then
      export "$key=$value"
    fi
  done < "$ENV_FILE"
}

load_env

if have_cmd python3; then pass "Python is installed"; else fail "python3 is missing"; fi
if have_cmd docker; then pass "Docker command is installed"; else warn "Docker command is missing; Docker deploy will not work"; fi
if docker compose version >/dev/null 2>&1; then pass "docker compose is available"; else warn "docker compose is unavailable"; fi

if [[ -f "$ENV_FILE" ]]; then
  pass ".env file exists at $ENV_FILE"
  perms="$(stat -f %Lp "$ENV_FILE" 2>/dev/null || stat -c %a "$ENV_FILE" 2>/dev/null || echo unknown)"
  if [[ "$perms" == "600" || "$perms" == "400" ]]; then
    pass ".env permissions are owner-only"
  else
    warn ".env permissions are $perms; prefer 600"
  fi
else
  warn ".env file not found; run python setup.py or ./scripts/quick_deploy.sh"
fi

AUTH_SECRET="${HONEYPOT_AUTH_SECRET:-}"
if [[ ${#AUTH_SECRET} -ge 32 && "$AUTH_SECRET" != "change-me-in-production" ]]; then
  pass "Auth secret is configured strongly"
else
  fail "Auth secret is missing, default, or too short"
fi

ADMIN_PASS="${HONEYPOT_ADMIN_PASS:-}"
if [[ ${#ADMIN_PASS} -ge 12 && ! "$ADMIN_PASS" =~ ^(admin|secret|password|admin123|changeme|default)$ ]]; then
  pass "Admin password baseline looks strong"
else
  warn "Admin password is missing or weak; setup/bootstrap may still be pending"
fi

BIND_HOST="${HONEYPOT_BIND_HOST:-127.0.0.1}"
if [[ "$BIND_HOST" == "127.0.0.1" || "$BIND_HOST" == "localhost" || "$BIND_HOST" == "::1" ]]; then
  pass "Dashboard bind host is private ($BIND_HOST)"
else
  warn "Dashboard bind host is $BIND_HOST; protect it with firewall/VPN/reverse proxy auth"
fi

DB_PATH="${HONEYPOT_DB_PATH:-$ROOT_DIR/honeypot.db}"
DB_PARENT="$(dirname "$DB_PATH")"
if [[ -d "$DB_PARENT" && -w "$DB_PARENT" ]]; then
  pass "Database directory is writable ($DB_PARENT)"
else
  fail "Database directory is not writable or missing ($DB_PARENT)"
fi

if [[ -f ml/model.pkl && -f ml/vectorizer.pkl && -f ml/artifacts.sha256 ]]; then
  pass "ML artifacts and manifest exist"
else
  warn "ML artifacts or manifest missing; run python ml/train.py if classifier should be active"
fi

if [[ "${HONEYPOT_ALERTS_ENABLED:-false}" =~ ^(1|true|yes|on)$ ]]; then
  configured=0
  [[ -n "${SLACK_WEBHOOK_URL:-}" ]] && configured=1
  [[ -n "${DISCORD_WEBHOOK_URL:-}" ]] && configured=1
  [[ -n "${N8N_WEBHOOK_URL:-}" ]] && configured=1
  [[ -n "${TELEGRAM_BOT_TOKEN:-}" && -n "${TELEGRAM_CHAT_ID:-}" ]] && configured=1
  [[ -n "${SMTP_HOST:-}" && -n "${SMTP_TO:-}" ]] && configured=1
  if [[ "$configured" == "1" ]]; then pass "Alerts enabled with at least one configured provider"; else warn "Alerts enabled but no complete provider is configured"; fi
else
  pass "Alerts are disabled or intentionally optional"
fi

if [[ "$MODE" == "online" ]]; then
  HEALTH_URL="http://127.0.0.1:${HONEYPOT_DASHBOARD_PORT:-5050}/api/health"
  if have_cmd curl && curl -fsS --max-time 3 "$HEALTH_URL" >/dev/null 2>&1; then
    pass "Dashboard health endpoint responded ($HEALTH_URL)"
  else
    warn "Dashboard health endpoint did not respond; start HoneyPot or run with --offline"
  fi
else
  pass "Offline mode selected; skipped live dashboard health check"
fi

echo "Summary: PASS=$PASS_COUNT WARN=$WARN_COUNT FAIL=$FAIL_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
exit 0
