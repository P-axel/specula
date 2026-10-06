#!/usr/bin/env bash
# Appelé par systemd au démarrage — restaure la dernière stack Specula active.
# Ollama n'est jamais démarré automatiquement ici (restart: "no" dans compose).
set -e

SPECULA_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SPECULA_DIR"

# Nettoyage des PIDs obsolètes du précédent run
find runtime/ -name "*.pid" -delete 2>/dev/null || true

# Sans état sauvegardé, Specula n'a jamais été lancé ou a été arrêté proprement
if [ ! -f .specula-state ]; then
    echo "[specula] Aucun état sauvegardé — démarrage ignoré."
    exit 0
fi

. .specula-state
set -a; . .env; set +a

# Détection de l'interface réseau si non sauvegardée dans l'état
if [ -z "${SURICATA_INTERFACE:-}" ]; then
    SURICATA_INTERFACE=$(ip -o link show \
        | awk -F': ' '{print $2}' \
        | sed 's/@.*//' \
        | grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|tun|tap|wg[0-9]*|zt)' \
        | grep -E '^(eth|en|ens|enp|eno|wlan|wl|enx)' \
        | head -n1 || true)
fi

COMPOSE="docker compose -f deploy/docker/core/docker-compose.yml"
mkdir -p runtime/logs/suricata

case "${SPECULA_PROFILE:-base}" in
    wazuh|ai)
        # Profil AI : Ollama n'est pas redémarré automatiquement.
        # Le backend utilisera OLLAMA_BASE_URL depuis .env si Ollama est disponible.
        SURICATA_INTERFACE="$SURICATA_INTERFACE" \
            $COMPOSE --env-file .env --profile wazuh up -d --remove-orphans
        ;;
    *)
        SURICATA_INTERFACE="$SURICATA_INTERFACE" \
            $COMPOSE --env-file .env up -d --remove-orphans
        ;;
esac

echo "[specula] Stack '${SPECULA_PROFILE:-base}' restaurée au démarrage."
