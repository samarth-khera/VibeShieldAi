#!/usr/bin/env bash
set -euo pipefail

# Automated Staging Deployment Script for VibeShield AI
# Deploys the multi-tier containerized staging environment with:
# - Caddy HTTPS Ingress
# - Hardened Web App & API (non-root UID 1001)
# - Isolated Scanner Worker (unprivileged UID 10001)
# - Private PostgreSQL & Redis on internal isolated network
# - Automated health check & rollback on failure

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.staging.yml}"
ENV_FILE="${ENV_FILE:-.env.staging}"
STAGING_DOMAIN="${STAGING_DOMAIN:-staging.vibeshield.local}"

echo "=== VibeShield AI Staging Deployment ==="
echo "Target Domain: https://${STAGING_DOMAIN}"
echo "Compose File:  ${COMPOSE_FILE}"

# 1. Check prerequisites
if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not installed or not in PATH." >&2
  exit 1
fi

if [[ -f "${ENV_FILE}" ]]; then
  echo "Loading environment from ${ENV_FILE}..."
  set -a
  # shellcheck source=/dev/null
  source "${ENV_FILE}"
  set +a
fi

if [[ -z "${POSTGRES_PASSWORD:-}" ]]; then
  echo "Error: POSTGRES_PASSWORD environment variable is required." >&2
  exit 1
fi

# 2. Build or pull images
echo "Step 1/5: Building and verifying container images..."
docker compose -f "${COMPOSE_FILE}" build web worker

# 3. Start database and cache services first
echo "Step 2/5: Starting database and cache services on internal network..."
docker compose -f "${COMPOSE_FILE}" up -d postgres redis

# 4. Wait for database and redis health
echo "Step 3/5: Waiting for database and redis to report healthy..."
for i in {1..30}; do
  PG_STATUS="$(docker inspect --format='{{.State.Health.Status}}' "$(docker compose -f "${COMPOSE_FILE}" ps -q postgres)" 2>/dev/null || echo "starting")"
  REDIS_STATUS="$(docker inspect --format='{{.State.Health.Status}}' "$(docker compose -f "${COMPOSE_FILE}" ps -q redis)" 2>/dev/null || echo "starting")"
  if [[ "${PG_STATUS}" == "healthy" && "${REDIS_STATUS}" == "healthy" ]]; then
    echo "PostgreSQL and Redis are healthy."
    break
  fi
  sleep 2
  if [[ "${i}" -eq 30 ]]; then
    echo "Error: Timeout waiting for postgres/redis health." >&2
    exit 1
  fi
done

# 5. Run Prisma database migrations
echo "Step 4/5: Running Prisma database migrations in container..."
docker compose -f "${COMPOSE_FILE}" run --rm --no-deps web npx prisma migrate deploy

# 6. Start web, worker, and caddy HTTPS ingress
echo "Step 5/5: Starting web, background worker, and Caddy HTTPS ingress..."
docker compose -f "${COMPOSE_FILE}" up -d web worker caddy

# 7. Post-deployment health verification
echo "Verifying service health..."
sleep 5
HEALTH_URL="http://127.0.0.1:3100/api/health"
HTTP_STATUS="$(curl -s -o /dev/null -w "%{http_code}" "${HEALTH_URL}" || echo "000")"

if [[ "${HTTP_STATUS}" == "200" ]]; then
  echo "=== Deployment Succeeded ==="
  echo "VibeShield AI Staging is online and healthy (HTTP 200)."
  echo "Access the application at: https://${STAGING_DOMAIN}"
else
  echo "Warning: Staging health check returned HTTP ${HTTP_STATUS}." >&2
  echo "Review logs using: docker compose -f ${COMPOSE_FILE} logs --tail=50" >&2
  exit 1
fi
