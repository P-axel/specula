#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="Specula"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="${ROOT_DIR}/deploy/master/wazuh/single-node"
WAZUH_CONFIG_DIR="${WAZUH_DIR}/config"
WAZUH_CERT_SRC_DIR="${WAZUH_CONFIG_DIR}/wazuh_indexer_ssl_certs"
WAZUH_RUNTIME_DIR="${ROOT_DIR}/runtime/wazuh/single-node"
WAZUH_CERT_DST_DIR="${WAZUH_RUNTIME_DIR}/certs"

FRONT_URL="http://localhost:5173"
API_URL="http://127.0.0.1:8000/docs"
WAZUH_URL="https://localhost:8443"

CERTS_COMPOSE_FILE="${WAZUH_DIR}/generate-indexer-certs.yml"
CERTS_SERVICE="generator"

have_runtime_certs() {
  [ -f "${WAZUH_CERT_DST_DIR}/root-ca.pem" ] &&
  [ -f "${WAZUH_CERT_DST_DIR}/wazuh.indexer.pem" ] &&
  [ -f "${WAZUH_CERT_DST_DIR}/wazuh.indexer-key.pem" ] &&
  [ -f "${WAZUH_CERT_DST_DIR}/admin.pem" ] &&
  [ -f "${WAZUH_CERT_DST_DIR}/admin-key.pem" ]
}

echo "========================================"
echo " Starting ${PROJECT_NAME} deployment"
echo "========================================"
echo ""

if ! command -v docker >/dev/null 2>&1; then
  echo "Error: Docker is not installed."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Error: Docker Compose is not available."
  exit 1
fi

if [ ! -d "$WAZUH_DIR" ]; then
  echo "Error: Wazuh directory not found:"
  echo "  $WAZUH_DIR"
  exit 1
fi

mkdir -p "$WAZUH_CERT_DST_DIR"

echo "[0/5] Checking Wazuh certificates..."

if ! have_runtime_certs; then
  echo "Wazuh certificates not found in runtime."
  echo "Generating certificates..."

  (
    cd "$WAZUH_DIR"
    docker compose -f "$(basename "$CERTS_COMPOSE_FILE")" run --rm "$CERTS_SERVICE"
  )

  if [ ! -d "$WAZUH_CERT_SRC_DIR" ]; then
    echo "Error: generated certificate source directory not found:"
    echo "  $WAZUH_CERT_SRC_DIR"
    exit 1
  fi

  cp -f "${WAZUH_CERT_SRC_DIR}/root-ca.pem" "${WAZUH_CERT_DST_DIR}/root-ca.pem"
  cp -f "${WAZUH_CERT_SRC_DIR}/wazuh.indexer.pem" "${WAZUH_CERT_DST_DIR}/wazuh.indexer.pem"
  cp -f "${WAZUH_CERT_SRC_DIR}/wazuh.indexer-key.pem" "${WAZUH_CERT_DST_DIR}/wazuh.indexer-key.pem"
  cp -f "${WAZUH_CERT_SRC_DIR}/admin.pem" "${WAZUH_CERT_DST_DIR}/admin.pem"
  cp -f "${WAZUH_CERT_SRC_DIR}/admin-key.pem" "${WAZUH_CERT_DST_DIR}/admin-key.pem"

  chmod 600 "${WAZUH_CERT_DST_DIR}"/* || true
else
  echo "Wazuh certificates already present."
fi

echo ""
echo "[1/5] Starting Wazuh stack..."
(
  cd "$WAZUH_DIR"
  docker compose up -d --remove-orphans
)

echo ""
echo "[2/5] Building and starting Specula containers..."
(
  cd "$ROOT_DIR"
  docker compose up --build -d --remove-orphans
)

echo ""
echo "[3/5] Waiting for services to become ready..."

max_attempts=90
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
    echo "Useful commands:"
    echo "  docker compose logs -f"
    echo "  (cd $WAZUH_DIR && docker compose logs -f)"
    exit 1
  fi

  attempt=$((attempt + 1))
  sleep 2
done

echo ""
echo "[4/5] Services are ready."
echo ""
echo "Specula Console : ${FRONT_URL}"
echo "Specula API Docs: ${API_URL}"
echo "Wazuh Dashboard : ${WAZUH_URL}"
echo ""