#!/usr/bin/env bash
set -euo pipefail

# Controlled OSV-Scanner database pre-caching procedure.
# Runs outside the isolated scanner (which has network_mode: none).
# Downloads and caches OSV vulnerability databases to a volume that is
# mounted READ-ONLY into isolated scanner jobs.

CACHE_DIR="${OSV_CACHE_DIR:-${HOME}/.cache/osv-scanner}"
mkdir -p "${CACHE_DIR}"
chmod 0700 "${CACHE_DIR}"

echo "Updating OSV-Scanner offline vulnerability database in ${CACHE_DIR}..."
if command -v osv-scanner >/dev/null 2>&1; then
  osv-scanner --download-offline-databases
  echo "OSV database cache successfully updated."
else
  echo "osv-scanner binary not found in PATH." >&2
  exit 1
fi
