#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_NAME="${PROJECT_NAME:-Specula}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# -----------------------------------------------------------------------------
# Config files
# -----------------------------------------------------------------------------
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
ENV_EXAMPLE_FILE="${ENV_EXAMPLE_FILE:-${ROOT_DIR}/.env.example}"
ENV_LOCAL_FILE="${ENV_LOCAL_FILE:-${ROOT_DIR}/.env.local}"

# -----------------------------------------------------------------------------
# Upstream dependencies
# -----------------------------------------------------------------------------
UPSTREAM_WAZUH_DIR="${UPSTREAM_WAZUH_DIR:-${ROOT_DIR}/deploy/master/wazuh/single-node}"

# -----------------------------------------------------------------------------
# Runtime directories
# -----------------------------------------------------------------------------
SPECULA_RUNTIME_DIR="${SPECULA_RUNTIME_DIR:-${ROOT_DIR}/runtime}"
WAZUH_RUNTIME_DIR="${SPECULA_RUNTIME_DIR}/wazuh/single-node"
WAZUH_CERT_DST_DIR="${WAZUH_RUNTIME_DIR}/certs"

# Common upstream Wazuh cert output locations
WAZUH_CERT_SRC_DIR="${WAZUH_CERT_SRC_DIR:-${UPSTREAM_WAZUH_DIR}/config/wazuh_indexer_ssl_certs}"
WAZUH_CERT_ALT_SRC_DIR="${WAZUH_CERT_ALT_SRC_DIR:-${UPSTREAM_WAZUH_DIR}/certs}"

# -----------------------------------------------------------------------------
# URLs
# -----------------------------------------------------------------------------
FRONT_URL="${FRONT_URL:-http://localhost:5173}"
API_URL="${API_URL:-http://127.0.0.1:8000/docs}"
API_HEALTH_URL="${API_HEALTH_URL:-http://127.0.0.1:8000/health}"
WAZUH_URL="${WAZUH_URL:-https://localhost:8443}"

# -----------------------------------------------------------------------------
# Docker / Compose
# -----------------------------------------------------------------------------
SPECULA_COMPOSE_FILE="${SPECULA_COMPOSE_FILE:-${ROOT_DIR}/docker-compose.yml}"
CERTS_COMPOSE_FILE="${CERTS_COMPOSE_FILE:-${UPSTREAM_WAZUH_DIR}/generate-indexer-certs.yml}"
CERTS_SERVICE="${CERTS_SERVICE:-generator}"

# -----------------------------------------------------------------------------
# Networks / volumes
# -----------------------------------------------------------------------------
SPECULA_NETWORK="${SPECULA_NETWORK:-specula-net}"
WAZUH_LOGS_VOLUME="${WAZUH_LOGS_VOLUME:-single-node_wazuh_logs}"

# -----------------------------------------------------------------------------
# Readiness
# -----------------------------------------------------------------------------
MAX_ATTEMPTS="${MAX_ATTEMPTS:-120}"
SLEEP_SECONDS="${SLEEP_SECONDS:-2}"

# -----------------------------------------------------------------------------
# CLI flags
# -----------------------------------------------------------------------------
SHOW_LOGS_ON_SUCCESS=0
SHOW_HELP=0
PREFLIGHT_ONLY=0
FORCE_REBUILD=0
SKIP_WAZUH=0

for arg in "$@"; do
  case "$arg" in
    --log|--logs)
      SHOW_LOGS_ON_SUCCESS=1
      ;;
    --preflight)
      PREFLIGHT_ONLY=1
      ;;
    --rebuild)
      FORCE_REBUILD=1
      ;;
    --skip-wazuh)
      SKIP_WAZUH=1
      ;;
    -h|--help)
      SHOW_HELP=1
      ;;
    *)
      ;;
  esac
done

if [[ "$SHOW_HELP" -eq 1 ]]; then
  cat <<'EOF'
Usage:
  ./start-specula.sh [options]

Options:
  --log, --logs   Show Specula logs after successful startup
  --preflight     Validate environment and exit without starting containers
  --rebuild       Force image rebuild for Specula services
  --skip-wazuh    Skip Wazuh startup (useful if already running)
  -h, --help      Show this help
EOF
  exit 0
fi

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
log() {
  printf '%s\n' "$*"
}

info() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

fail() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

# -----------------------------------------------------------------------------
# Error trap
# -----------------------------------------------------------------------------
on_error() {
  local exit_code=$?
  printf '\n' >&2
  printf '[ERROR] Startup failed near line %s while running: %s\n' "${BASH_LINENO[0]}" "${BASH_COMMAND}" >&2
  exit "$exit_code"
}
trap on_error ERR

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
have_command() {
  command -v "$1" >/dev/null 2>&1
}

load_env_file() {
  local file="$1"
  if [[ -f "$file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

ensure_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    return 0
  fi

  if [[ -f "$ENV_EXAMPLE_FILE" ]]; then
    cp "$ENV_EXAMPLE_FILE" "$ENV_FILE"
    warn ".env was missing. Created it from .env.example. Review it if needed."
    return 0
  fi

  fail "No .env found and no .env.example available."
}

require_readable_file() {
  local file="$1"
  [[ -f "$file" ]] || fail "Required file not found: ${file}"
}

require_directory() {
  local dir="$1"
  [[ -d "$dir" ]] || fail "Required directory not found: ${dir}"
}

require_env_var() {
  local var_name="$1"
  local value="${!var_name:-}"
  [[ -n "$value" ]] || fail "Required environment variable is missing: ${var_name}"
}

check_port_warning() {
  local port="$1"

  if have_command lsof && lsof -iTCP:"${port}" -sTCP:LISTEN >/dev/null 2>&1; then
    warn "Port ${port} appears to already be in use."
  fi
}

check_url() {
  local url="$1"
  curl -fsS "$url" >/dev/null 2>&1
}

check_front() {
  check_url "$FRONT_URL"
}

check_api_docs() {
  check_url "$API_URL"
}

check_api_health() {
  check_url "$API_HEALTH_URL"
}

detect_suricata_interface() {
  if ! have_command ip; then
    return 0
  fi

  ip -o link show \
    | awk -F': ' '{print $2}' \
    | sed 's/@.*//' \
    | grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|tun|tap|wg[0-9]*|zt[[:alnum:]]+)$' \
    | grep -E '^(eth|en|ens|enp|eno|wlan|wl)' \
    | head -n1 || true
}

validate_suricata_interface() {
  local iface="$1"
  if ! have_command ip; then
    return 0
  fi
  ip link show "$iface" >/dev/null 2>&1
}

have_runtime_certs() {
  [[ -f "${WAZUH_CERT_DST_DIR}/root-ca.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/wazuh.indexer.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/wazuh.indexer-key.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/admin.pem" ]] &&
  [[ -f "${WAZUH_CERT_DST_DIR}/admin-key.pem" ]]
}

resolve_cert_source_dir() {
  if [[ -d "$WAZUH_CERT_SRC_DIR" ]]; then
    printf '%s\n' "$WAZUH_CERT_SRC_DIR"
    return 0
  fi

  if [[ -d "$WAZUH_CERT_ALT_SRC_DIR" ]]; then
    printf '%s\n' "$WAZUH_CERT_ALT_SRC_DIR"
    return 0
  fi

  return 1
}

copy_runtime_certs() {
  local src_dir="$1"

  [[ -f "${src_dir}/root-ca.pem" ]] || fail "Missing certificate: ${src_dir}/root-ca.pem"
  [[ -f "${src_dir}/wazuh.indexer.pem" ]] || fail "Missing certificate: ${src_dir}/wazuh.indexer.pem"
  [[ -f "${src_dir}/wazuh.indexer-key.pem" ]] || fail "Missing certificate: ${src_dir}/wazuh.indexer-key.pem"
  [[ -f "${src_dir}/admin.pem" ]] || fail "Missing certificate: ${src_dir}/admin.pem"
  [[ -f "${src_dir}/admin-key.pem" ]] || fail "Missing certificate: ${src_dir}/admin-key.pem"

  cp -f "${src_dir}/root-ca.pem" "${WAZUH_CERT_DST_DIR}/"
  cp -f "${src_dir}/wazuh.indexer.pem" "${WAZUH_CERT_DST_DIR}/"
  cp -f "${src_dir}/wazuh.indexer-key.pem" "${WAZUH_CERT_DST_DIR}/"
  cp -f "${src_dir}/admin.pem" "${WAZUH_CERT_DST_DIR}/"
  cp -f "${src_dir}/admin-key.pem" "${WAZUH_CERT_DST_DIR}/"

  chmod 600 "${WAZUH_CERT_DST_DIR}/"* 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Docker resolution
# -----------------------------------------------------------------------------
DOCKER_CMD=()

resolve_docker() {
  have_command docker || fail "Docker is not installed."
  have_command curl || fail "curl is not installed."

  if docker info >/dev/null 2>&1; then
    DOCKER_CMD=(docker)
    return 0
  fi

  if have_command sudo && sudo -n docker info >/dev/null 2>&1; then
    DOCKER_CMD=(sudo docker)
    return 0
  fi

  fail "Docker is installed but not accessible. Start Docker or grant this user access to Docker."
}

docker_run() {
  "${DOCKER_CMD[@]}" "$@"
}

docker_compose_root() {
  docker_run compose -f "$SPECULA_COMPOSE_FILE" "$@"
}

docker_compose_wazuh() {
  (
    cd "$UPSTREAM_WAZUH_DIR"
    docker_run compose "$@"
  )
}

docker_compose_certs() {
  (
    cd "$UPSTREAM_WAZUH_DIR"
    docker_run compose -f "$CERTS_COMPOSE_FILE" "$@"
  )
}

network_exists() {
  docker_run network inspect "$SPECULA_NETWORK" >/dev/null 2>&1
}

volume_exists() {
  docker_run volume inspect "$WAZUH_LOGS_VOLUME" >/dev/null 2>&1
}

container_networks() {
  local container_name="$1"
  docker_run inspect "$container_name" --format '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# Validation / preparation
# -----------------------------------------------------------------------------
log "========================================"
log " Starting ${PROJECT_NAME} deployment"
log "========================================"
log ""
log "This may take several minutes on first startup."

ensure_env_file
load_env_file "$ENV_FILE"
load_env_file "$ENV_LOCAL_FILE"

require_readable_file "$SPECULA_COMPOSE_FILE"
require_directory "$UPSTREAM_WAZUH_DIR"
require_readable_file "$CERTS_COMPOSE_FILE"

resolve_docker
docker_run compose version >/dev/null 2>&1 || fail "Docker Compose is not available."

check_port_warning 5173
check_port_warning 8000
check_port_warning 8443
check_port_warning 55000
check_port_warning 9200

mkdir -p "$WAZUH_CERT_DST_DIR"
mkdir -p "${ROOT_DIR}/deploy/master/suricata/logs"
mkdir -p "${ROOT_DIR}/deploy/master/suricata/rules"

if [[ -r /proc/meminfo ]]; then
  total_kb="$(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  total_mb=$((total_kb / 1024))
  if [[ "$total_mb" -lt 4096 ]]; then
    warn "Detected RAM: ${total_mb} MB. Recommended: at least 4096 MB."
  fi
fi

if [[ -z "${TZ:-}" ]]; then
  export TZ="Europe/Paris"
fi

if [[ -z "${SURICATA_INTERFACE:-}" ]]; then
  detected_iface="$(detect_suricata_interface || true)"
  if [[ -n "${detected_iface:-}" ]]; then
    export SURICATA_INTERFACE="$detected_iface"
    warn "SURICATA_INTERFACE was not set. Auto-detected interface: ${SURICATA_INTERFACE}"
  fi
fi

[[ -n "${SURICATA_INTERFACE:-}" ]] || fail "SURICATA_INTERFACE is not set and no suitable interface was auto-detected."
validate_suricata_interface "${SURICATA_INTERFACE}" || fail "SURICATA_INTERFACE does not exist on this machine: ${SURICATA_INTERFACE}"

require_env_var WAZUH_BASE_URL
require_env_var WAZUH_INDEXER_URL

case "${WAZUH_BASE_URL}" in
  *host.docker.internal*|*localhost*|*127.0.0.1*)
    warn "WAZUH_BASE_URL uses a host-local address. For Docker-to-Docker communication, prefer a container name on the shared Docker network."
    ;;
esac

case "${WAZUH_INDEXER_URL}" in
  *host.docker.internal*|*localhost*|*127.0.0.1*)
    warn "WAZUH_INDEXER_URL uses a host-local address. For Docker-to-Docker communication, prefer a container name on the shared Docker network."
    ;;
esac

if [[ "$PREFLIGHT_ONLY" -eq 1 ]]; then
  log ""
  log "Preflight checks passed."
  log "Docker access       : OK"
  log "Compose file        : ${SPECULA_COMPOSE_FILE}"
  log "Wazuh upstream      : ${UPSTREAM_WAZUH_DIR}"
  log "Timezone            : ${TZ}"
  log "Suricata interface  : ${SURICATA_INTERFACE}"
  log "Wazuh base URL      : ${WAZUH_BASE_URL}"
  log "Wazuh indexer URL   : ${WAZUH_INDEXER_URL}"
  exit 0
fi

log "[0/7] Checking Wazuh certificates..."

if ! have_runtime_certs; then
  info "Wazuh certificates not found in runtime."
  info "Generating certificates..."

  docker_compose_certs run --rm "$CERTS_SERVICE"

  cert_src="$(resolve_cert_source_dir || true)"
  [[ -n "${cert_src:-}" ]] || fail "Unable to locate generated certificate directory."

  copy_runtime_certs "$cert_src"
  have_runtime_certs || fail "Certificates were not copied correctly into ${WAZUH_CERT_DST_DIR}"

  info "Certificates generated and copied into runtime."
else
  info "Wazuh certificates already present."
fi

log ""
log "[1/7] Ensuring Docker network exists..."
if ! network_exists; then
  docker_run network create "$SPECULA_NETWORK" >/dev/null
  info "Created network: ${SPECULA_NETWORK}"
else
  info "Network already present: ${SPECULA_NETWORK}"
fi

if [[ "$SKIP_WAZUH" -eq 0 ]]; then
  log ""
  log "[2/7] Starting Wazuh stack..."
  docker_compose_wazuh up -d --remove-orphans
else
  log ""
  log "[2/7] Skipping Wazuh startup as requested."
fi

log ""
log "[3/7] Verifying shared Wazuh volume..."
if ! volume_exists; then
  fail "Required Docker volume missing: ${WAZUH_LOGS_VOLUME}"
fi
info "Shared Wazuh volume available: ${WAZUH_LOGS_VOLUME}"

log ""
log "[4/7] Building and starting Specula containers..."
if [[ "$FORCE_REBUILD" -eq 1 ]]; then
  docker_compose_root up --build -d --remove-orphans
else
  docker_compose_root up -d --build --remove-orphans
fi

log ""
log "[5/7] Waiting for core services..."

attempt=1
until check_front && check_api_docs && check_api_health; do
  if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
    log ""
    log "Deployment started, but readiness check timed out."
    log ""
    log "Useful commands:"
    log "  docker compose -f ${SPECULA_COMPOSE_FILE} logs -f"
    log "  (cd ${UPSTREAM_WAZUH_DIR} && docker compose logs -f)"
    log ""
    fail "Frontend and/or API did not become reachable in time."
  fi

  printf '\rWaiting... %d/%d' "$attempt" "$MAX_ATTEMPTS"
  attempt=$((attempt + 1))
  sleep "$SLEEP_SECONDS"
done
printf '\n'

log ""
log "[6/7] Verifying container network attachment..."
backend_container="$(docker_compose_root ps -q specula-backend 2>/dev/null || true)"
if [[ -n "${backend_container:-}" ]]; then
  backend_networks="$(docker_run inspect "$backend_container" --format '{{range $k, $v := .NetworkSettings.Networks}}{{println $k}}{{end}}' || true)"
  if ! printf '%s\n' "$backend_networks" | grep -Fxq "$SPECULA_NETWORK"; then
    warn "specula-backend is not attached to expected Docker network '${SPECULA_NETWORK}'."
    warn "Detected networks:"
    printf '%s\n' "$backend_networks" >&2
  else
    info "specula-backend is attached to network: ${SPECULA_NETWORK}"
  fi
else
  warn "Unable to determine specula-backend container ID."
fi

log ""
log "🌐 Specula Console : ${FRONT_URL}"
log "📚 Specula API Docs: ${API_URL}"
log "🛡️ Wazuh Dashboard : ${WAZUH_URL}"
log ""
warn "⚠️  Wazuh uses a self-signed certificate. Your browser may ask you to accept a security exception."

if [[ "$SHOW_LOGS_ON_SUCCESS" -eq 1 ]]; then
  log ""
  log "Streaming Specula logs..."
  docker_compose_root logs -f
fi