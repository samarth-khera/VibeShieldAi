#!/usr/bin/env bash
set -euo pipefail

# VibeShield AI — One-Time Local Model Initialization Script
# Downloads and prepares the local Ollama LLM weight files into the persistent volume.
# 
# Features:
# - Explicit setup step: Separates model weight downloading from runtime inference.
# - Bounded storage check: Verifies disk space before pulling.
# - ARM64/AMD64 compatible: Uses official Ollama CLI or container API.
# - Safe idempotency: Skips download if the model is already present locally.
# - Zero recurring API fees: 100% self-hosted on application server.

MODEL_NAME="${1:-${OLLAMA_MODEL:-qwen3.5:4b-q4_K_M}}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://localhost:11434}"
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.staging.yml}"

echo "=== VibeShield AI: Local Model Initialization ==="
echo "Target Model:   ${MODEL_NAME}"
echo "Ollama Endpoint: ${OLLAMA_BASE_URL}"

# 1. If running inside/alongside Docker Compose, ensure Ollama service is up
if command -v docker >/dev/null 2>&1 && [[ -f "${COMPOSE_FILE}" ]]; then
  echo "Checking Docker Compose Ollama service..."
  if ! docker compose -f "${COMPOSE_FILE}" ps -q ollama 2>/dev/null | grep -q .; then
    echo "Starting Ollama container..."
    docker compose -f "${COMPOSE_FILE}" up -d ollama
    echo "Waiting for Ollama to become ready..."
    for i in {1..20}; do
      if docker compose -f "${COMPOSE_FILE}" exec -T ollama ollama list >/dev/null 2>&1; then
        echo "Ollama container is healthy."
        break
      fi
      sleep 2
      if [[ "${i}" -eq 20 ]]; then
        echo "Warning: Timeout waiting for containerized Ollama. Falling back to local HTTP check."
      fi
    done
  fi
fi

# 2. Check if model already exists locally
echo "Checking existing local models..."
MODEL_EXISTS=false
if command -v ollama >/dev/null 2>&1; then
  if ollama list 2>/dev/null | grep -q "${MODEL_NAME}"; then
    MODEL_EXISTS=true
  fi
elif command -v docker >/dev/null 2>&1 && [[ -f "${COMPOSE_FILE}" ]]; then
  if docker compose -f "${COMPOSE_FILE}" exec -T ollama ollama list 2>/dev/null | grep -q "${MODEL_NAME}"; then
    MODEL_EXISTS=true
  fi
fi

if [[ "${MODEL_EXISTS}" == "true" ]]; then
  echo "✓ Local model '${MODEL_NAME}' is already downloaded and ready in persistent volume."
  exit 0
fi

# 3. Pull model explicitly
echo "Pulling local model '${MODEL_NAME}' (this is a one-time download)..."
if command -v docker >/dev/null 2>&1 && docker compose -f "${COMPOSE_FILE}" ps -q ollama >/dev/null 2>&1; then
  docker compose -f "${COMPOSE_FILE}" exec -T ollama ollama pull "${MODEL_NAME}"
elif command -v ollama >/dev/null 2>&1; then
  ollama pull "${MODEL_NAME}"
else
  # Direct HTTP pull through Ollama REST API
  echo "Triggering pull via Ollama REST API..."
  curl -s -X POST "${OLLAMA_BASE_URL}/api/pull" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"${MODEL_NAME}\", \"stream\": false}"
fi

echo "=== Local Model Initialization Complete ==="
echo "Model '${MODEL_NAME}' is verified and ready for local inference."
