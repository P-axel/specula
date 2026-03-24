#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="${PROJECT_NAME:-Specula}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Upstream dependencies
UPSTREAM_WAZUH_DIR="${UPSTREAM_WAZUH_DIR:-${ROOT_DIR}/deploy/master/wazuh/single-node}"

# Specula runtime
SPECULA_RUNTIME_DIR="${SPECULA_RUNTIME_DIR:-${ROOT_DIR}/runtime}"
WAZUH_RUNTIME_DIR="${SPECULA_RUNTIME_DIR}/wazuh/single-node"
WAZUH_CERT_DST_DIR="${WAZUH_RUNTIME_DIR}/certs"

# URLs
FRONT_URL="${FRONT_URL:-http://localhost:5173}"
API_URL="${API_URL:-http://127.0.0.1:8000/docs}"
WAZUH_URL="${WAZUH_URL:-https://localhost:8443}"

# Wazuh cert generation
CERTS_COMPOSE_FILE="${CERTS_COMPOSE_FILE:-${UPSTREAM_WAZUH_DIR}/generate-indexer-certs.yml}"
CERTS_SERVICE="${CERTS_SERVICE:-generator}"

MAX_ATTEMPTS="${MAX_ATTEMPTS:-90}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"

log() {
  printf '%s\n' "$*"
}

warn() {
  printf 'Warning: %s\n' "$*" >&2
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

have_command() {
  command -v "$1" >/dev/null 2>&1
}

have_runtime_certs() {
  [[ -f "${WAZUH_CERT_DST_DIR}/root-ca.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/wazuh.indexer.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/wazuh.indexer-key.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/admin.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/admin-key.pem" ]]
}

check_front() {
  curl -fsS "$FRONT_URL" >/dev/null 2>&1
}

check_api() {
  curl -fsS "$API_URL" >/dev/null 2>&1
}

check_port_warning() {
  local port="$1"

  if have_command lsof; then
    if lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
      warn "Port ${port} appears to already be in use."
    fi
  fi
}

log "========================================"
log " Starting ${PROJECT_NAME} deployment"
log "========================================"
log ""

log "This may take several minutes on first startup."

have_command docker || fail "Docker is not installed."
docker compose version >/dev/null 2>&1 || fail "Docker Compose is not available."
have_command curl || fail "curl is not installed."

if ! docker info >/dev/null 2>&1; then
  fail "Docker is installed but not accessible. Check that Docker is running and that your user has permission to use it."
fi

[[ -d "$UPSTREAM_WAZUH_DIR" ]] || fail "Wazuh upstream directory not found: ${UPSTREAM_WAZUH_DIR}"

check_port_warning 5173
check_port_warning 8000
check_port_warning 8443

mkdir -p "$WAZUH_CERT_DST_DIR"

if [[ -r /proc/meminfo ]]; then
  total_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  total_mb=$((total_kb / 1024))
  if [[ "$total_mb" -lt 4096 ]]; then
    warn "Detected RAM: ${total_mb} MB. Recommended: at least 4096 MB."
  fi
fi

log "[0/5] Checking Wazuh certificates..."

if ! have_runtime_certs; then
  log "Wazuh certificates not found in runtime."
  log "Generating certificates..."

  (
    cd "$UPSTREAM_WAZUH_DIR"
    docker compose -f "$(basename "$CERTS_COMPOSE_FILE")" run --rm "$CERTS_SERVICE"
  )

  have_runtime_certs || fail "Certificates were not generated correctly in ${WAZUH_CERT_DST_DIR}"
  chmod 600 "${WAZUH_CERT_DST_DIR}"/* 2>/dev/null || true

  log "Certificates generated in runtime."
else
  log "Wazuh certificates already present."
fi

log ""
log "[1/5] Starting Wazuh stack..."
(
  cd "$UPSTREAM_WAZUH_DIR"
  docker compose up -d --remove-orphans
)

log ""
log "[2/5] Building and starting Specula containers..."
(
  cd "$ROOT_DIR"
  docker compose up --build -d --remove-orphans
)

log ""
log "[3/5] Waiting for services to become ready..."
log "Frontend: ${FRONT_URL}"
log "API docs: ${API_URL}"

attempt=1
until check_front && check_api; do
  if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
    log ""
    log "Deployment started, but readiness check timed out."
    log "Useful commands:"
    log "  docker compose logs -f"
    log "  (cd ${UPSTREAM_WAZUH_DIR} && docker compose logs -f)"
    exit 1
  fi

  printf '\rWaiting... %d/%d' "$attempt" "$MAX_ATTEMPTS"
  attempt=$((attempt + 1))
  sleep "$SLEEP_SECONDS"
done

printf '\n'

log ""
log "[4/5] Services are ready."
log ""
log "Specula Console : ${FRONT_URL}"
log "Specula API Docs: ${API_URL}"
log "Wazuh Dashboard : ${WAZUH_URL}"
log ""
warn "Wazuh uses a self-signed certificate. Your browser may ask you to accept a security exception."