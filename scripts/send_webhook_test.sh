#!/usr/bin/env bash
set -euo pipefail

# scripts/send_webhook_test.sh - send a test AdminReport to webhook receiver
# Usage: scripts/send_webhook_test.sh [PORT]

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PORT="${1:-8080}"

# Load WEBHOOK_SECRET from .env if present
if [[ -f .env ]]; then
  # shellcheck disable=SC2046
  export $(grep -E '^(WEBHOOK_SECRET)=' .env | xargs)
fi

if [[ -z "${WEBHOOK_SECRET:-}" ]]; then
  echo "ERROR: WEBHOOK_SECRET is not set. Set it in .env or export it."
  exit 1
fi

NOW_TS=$(date +%s)
# Create a sample payload
read -r -d '' PAYLOAD <<JSON
{
  "ip": "203.0.113.42",
  "username": "intruder-test",
  "attempts": 5,
  "timestamp": ${NOW_TS},
  "reason": "Multiple failed login attempts"
}
JSON

set -x
curl -sS -X POST \
  -H "Authorization: Bearer ${WEBHOOK_SECRET}" \
  -H "Content-Type: application/json" \
  --data "${PAYLOAD}" \
  http://localhost:${PORT}/webhook | jq .
