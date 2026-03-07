#!/usr/bin/env bash
set -euo pipefail

echo "[Specula] PostgreSQL status:"
docker compose -f postgres/compose.yml ps

echo
echo "[Specula] Wazuh status:"
docker compose -f wazuh/single-node/docker-compose.yml ps