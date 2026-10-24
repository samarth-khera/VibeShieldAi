#!/usr/bin/env bash
set -euo pipefail

# Database Migration Verification Script for VibeShield AI
# Verifies that all Prisma schema migrations have been applied cleanly.

echo "Checking Prisma migration status..."
npx prisma migrate status

echo "Migration verification passed. Database schema is up-to-date."
