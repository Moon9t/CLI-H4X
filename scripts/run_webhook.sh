#!/usr/bin/env bash
set -euo pipefail

# scripts/run_webhook.sh - run webhook receiver with .env variables
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -f "bin/webhook" ]]; then
  echo "Building webhook binary..."
  make webhook
fi

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  echo "Warning: .env not found. Using current environment vars."
fi

PORT="${1:-8080}"
echo "Starting webhook on port ${PORT} (health: http://localhost:${PORT}/health)"
exec ./bin/webhook -port "${PORT}"
