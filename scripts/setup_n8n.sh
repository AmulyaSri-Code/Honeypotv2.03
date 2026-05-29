#!/usr/bin/env bash
set -euo pipefail

COMPOSE_PROFILE=${COMPOSE_PROFILE:-automation}
N8N_CONTAINER=${N8N_CONTAINER:-honeypot_n8n}
WORKFLOW=${WORKFLOW:-n8n-workflows/honeypot-v3-critical-alert.json}
WORKFLOW_ID=${WORKFLOW_ID:-honeypot-v3-critical-alert-router}
WEBHOOK_URL=${WEBHOOK_URL:-http://127.0.0.1:5678/webhook/honeypot-v3-alert}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:5678/healthz}

if [ ! -f "$WORKFLOW" ]; then
  echo "Missing workflow file: $WORKFLOW" >&2
  exit 1
fi

printf 'Starting n8n with Docker Compose profile %s...\n' "$COMPOSE_PROFILE"
docker compose --profile "$COMPOSE_PROFILE" up -d n8n

printf 'Waiting for n8n health endpoint...\n'
for _ in $(seq 1 60); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS "$HEALTH_URL" >/dev/null

printf 'Validating workflow JSON...\n'
python3 -m json.tool "$WORKFLOW" >/dev/null

printf 'Copying workflow into %s...\n' "$N8N_CONTAINER"
docker cp "$WORKFLOW" "$N8N_CONTAINER:/tmp/honeypot-workflow.json"

printf 'Importing workflow...\n'
docker exec "$N8N_CONTAINER" n8n import:workflow --input=/tmp/honeypot-workflow.json

printf 'Publishing/activating workflow...\n'
if docker exec "$N8N_CONTAINER" n8n publish:workflow --id="$WORKFLOW_ID"; then
  true
else
  docker exec "$N8N_CONTAINER" n8n update:workflow --id="$WORKFLOW_ID" --active=true
fi

printf 'Restarting n8n so production webhooks register...\n'
docker compose --profile "$COMPOSE_PROFILE" restart n8n >/dev/null

printf 'Waiting for active workflow registration...\n'
for _ in $(seq 1 90); do
  if curl -fsS "$HEALTH_URL" >/dev/null 2>&1 && \
     docker logs --tail=120 "$N8N_CONTAINER" 2>&1 | grep -q "Activated workflow \"HoneyPot v3 - Critical Alert Router\""; then
    break
  fi
  sleep 1
done

printf 'Smoke testing production webhook...\n'
status=$(curl -sS -o /tmp/honeypot-n8n-smoke-response.txt -w '%{http_code}' \
  -X POST "$WEBHOOK_URL" \
  -H 'Content-Type: application/json' \
  -d '{"source":"HoneyPot v3","summary":"setup smoke test","severity":"critical","event":{"severity":"critical","ip":"127.0.0.1","service":"http","attack_category":"setup","command":"n8n smoke"}}')

if [ "$status" != "200" ]; then
  echo "Webhook smoke test failed with HTTP $status" >&2
  echo "Response body:" >&2
  cat /tmp/honeypot-n8n-smoke-response.txt >&2 || true
  echo "Recent n8n logs:" >&2
  docker logs --tail=120 "$N8N_CONTAINER" >&2 || true
  exit 1
fi

printf 'n8n setup complete. Webhook returned HTTP 200: %s\n' "$WEBHOOK_URL"
