#!/usr/bin/env bash
set -euo pipefail

echo "[Specula] Starting master deployment..."

if ! command -v docker >/dev/null 2>&1; then
  echo "[Specula] Docker is not installed."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "[Specula] Docker Compose plugin is not available."
  exit 1
fi

echo "[Specula] Starting PostgreSQL..."
docker compose -f postgres/compose.yml up -d

echo "[Specula] PostgreSQL started."
echo "[Specula] Wazuh deployment will be added next."