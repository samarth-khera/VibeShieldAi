#!/usr/bin/env bash
set -euo pipefail

# Database Restore Script for VibeShield AI
# Restores a compressed PostgreSQL backup file.
# Usage: ./scripts/restore-db.sh <path-to-backup.sql.gz>

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <path-to-backup.sql.gz>" >&2
  exit 1
fi

BACKUP_FILE="$1"

if [[ ! -f "${BACKUP_FILE}" ]]; then
  echo "Error: Backup file not found: ${BACKUP_FILE}" >&2
  exit 1
fi

echo "WARNING: Restoring will overwrite existing data with ${BACKUP_FILE}."
echo "Proceeding with restoration..."

if [[ -n "${DATABASE_URL:-}" ]]; then
  gunzip -c "${BACKUP_FILE}" | psql "${DATABASE_URL}"
else
  PG_CONTAINER="$(docker ps --filter "name=postgres" --format "{{.ID}}" | head -n 1)"
  if [[ -z "${PG_CONTAINER}" ]]; then
    echo "Error: No PostgreSQL container or DATABASE_URL found." >&2
    exit 1
  fi
  gunzip -c "${BACKUP_FILE}" | docker exec -i "${PG_CONTAINER}" psql -U vibeshield -d vibeshield
fi

echo "Database restoration completed successfully."
