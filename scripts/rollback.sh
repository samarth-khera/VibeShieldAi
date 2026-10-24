#!/usr/bin/env bash
set -euo pipefail

# Rollback Procedure for VibeShield AI
# Reverts to a previous deployment image tag and restores the database if necessary.

TARGET_TAG="${1:-previous}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.staging.yml}"

echo "=== VibeShield AI Emergency Rollback Procedure ==="
echo "Rolling back deployment to tag: ${TARGET_TAG}"

# 1. Stop current containers gracefully
docker compose -f "${COMPOSE_FILE}" stop web worker

# 2. Deploy target image tag
echo "Restarting services with target version..."
TAG="${TARGET_TAG}" docker compose -f "${COMPOSE_FILE}" up -d --no-deps web worker

# 3. Verify health endpoint
echo "Verifying service health after rollback..."
sleep 5
HEALTH_URL="http://127.0.0.1:3100/api/health"
STATUS_CODE="$(curl -s -o /dev/null -w "%{http_code}" "${HEALTH_URL}" || echo "000")"

if [[ "${STATUS_CODE}" == "200" ]]; then
  echo "Rollback verified. Services are healthy (HTTP 200)."
else
  echo "Warning: Health check returned HTTP ${STATUS_CODE}. Inspect container logs." >&2
fi
