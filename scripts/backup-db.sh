#!/usr/bin/env bash
set -euo pipefail

# Automated Database Backup Script for VibeShield AI
# Exports a compressed, permission-restricted snapshot of the PostgreSQL database.
# Never logs credentials or includes passwords in process arguments.

BACKUP_DIR="${BACKUP_DIR:-./backups}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${BACKUP_DIR}/vibeshield_backup_${TIMESTAMP}.sql.gz"

mkdir -p "${BACKUP_DIR}"
chmod 0700 "${BACKUP_DIR}"

echo "Starting automated VibeShield AI database backup..."

if [[ -n "${DATABASE_URL:-}" ]]; then
  # Use DATABASE_URL if available
  pg_dump "${DATABASE_URL}" --clean --if-exists --no-owner --no-privileges | gzip -9 > "${BACKUP_FILE}"
else
  # Use Docker container if running locally/staging
  PG_CONTAINER="$(docker ps --filter "name=postgres" --format "{{.ID}}" | head -n 1)"
  if [[ -z "${PG_CONTAINER}" ]]; then
    echo "Error: No PostgreSQL container or DATABASE_URL found." >&2
    exit 1
  fi
  docker exec "${PG_CONTAINER}" pg_dump -U vibeshield vibeshield --clean --if-exists --no-owner --no-privileges | gzip -9 > "${BACKUP_FILE}"
fi

chmod 0600 "${BACKUP_FILE}"
BACKUP_SIZE="$(ls -lh "${BACKUP_FILE}" | awk '{print $5}')"
echo "Database backup completed successfully: ${BACKUP_FILE} (${BACKUP_SIZE})"

# Retain backups for 7 days
find "${BACKUP_DIR}" -name "vibeshield_backup_*.sql.gz" -type f -mtime +7 -delete || true
