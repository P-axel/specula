#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/single-node/docker-compose.yml"

echo "[+] Pull de l'image Suricata..."
docker compose --env-file "$ROOT_DIR/.env" -f "$COMPOSE_FILE" pull

echo "[+] Redéploiement..."
docker compose --env-file "$ROOT_DIR/.env" -f "$COMPOSE_FILE" up -d

echo "[+] Upgrade terminé."