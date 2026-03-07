#!/usr/bin/env bash
set -euo pipefail

echo "[Specula] Pulling PostgreSQL updates..."
docker compose -f postgres/compose.yml pull

echo "[Specula] Pulling Wazuh updates..."
docker compose -f wazuh/single-node/docker-compose.yml pull

echo "[Specula] Recreating PostgreSQL..."
docker compose -f postgres/compose.yml up -d

echo "[Specula] Recreating Wazuh..."
docker compose -f wazuh/single-node/docker-compose.yml up -d

echo "[Specula] Upgrade complete."