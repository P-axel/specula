#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="Specula"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="${ROOT_DIR}/deploy/master/wazuh/single-node"

FRONT_URL="http://localhost:5173"
API_URL="http://127.0.0.1:8000/docs"
WAZUH_URL="https://localhost:8443"

echo "========================================"
echo " Starting ${PROJECT_NAME} deployment"
echo "========================================"
echo ""

# Check Docker
if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is not installed."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Error: Docker Compose is not available."
  exit 1
fi

echo "[0/4] Checking Wazuh source..."

if [ -f "${ROOT_DIR}/.gitmodules" ] && git config --file "${ROOT_DIR}/.gitmodules" --get-regexp '^submodule\..*\.path$' | grep -q 'deploy/master/wazuh$'; then
  echo "Wazuh submodule detected, initializing..."
  git submodule update --init --recursive
else
  echo "No Wazuh submodule declared, skipping submodule initialization."
fi

# Check Wazuh dir
if [ ! -d "$WAZUH_DIR" ]; then
  echo "Error: Wazuh directory not found at:"
  echo "  $WAZUH_DIR"
  exit 1
fi

echo "[1/4] Starting Wazuh stack..."
(
  cd "$WAZUH_DIR"
  docker compose up -d
)

echo ""
echo "[2/4] Building and starting Specula containers..."
(
  cd "$ROOT_DIR"
  docker compose up --build -d
)

echo ""
echo "[3/4] Waiting for services to become ready..."

max_attempts=60
attempt=1

check_front() {
  curl -fsS "$FRONT_URL" >/dev/null 2>&1
}

check_api() {
  curl -fsS "$API_URL" >/dev/null 2>&1
}

until check_front && check_api; do
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo ""
    echo "Deployment started, but readiness check timed out."
    echo ""
    echo "Useful commands:"
    echo "  docker compose logs -f"
    echo "  (cd $WAZUH_DIR && docker compose logs -f)"
    exit 1
  fi

  attempt=$((attempt + 1))
  sleep 2
done

echo ""
echo "[4/4] Services are ready."
echo ""
echo "========================================"
echo " ${PROJECT_NAME} is up"
echo "========================================"
echo ""
echo "Specula Console : ${FRONT_URL}"
echo "Specula API Docs: ${API_URL}"
echo "Wazuh Dashboard : ${WAZUH_URL}"
echo ""
echo "Useful commands:"
echo "  docker compose logs -f"
echo "  docker compose down"
echo "  (cd $WAZUH_DIR && docker compose logs -f)"
echo "  (cd $WAZUH_DIR && docker compose down)"
echo ""