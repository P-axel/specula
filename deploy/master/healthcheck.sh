#!/usr/bin/env bash
set -euo pipefail

echo "[Specula] PostgreSQL status:"
docker compose -f postgres/compose.yml ps