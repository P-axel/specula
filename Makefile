COMPOSE  = docker compose -f deploy/docker/core/docker-compose.yml
ENV_FILE = .env

.PHONY: up up-wazuh down reset rebuild logs ps wazuh-certs help

# ─── Aide ──────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Specula — Commandes disponibles"
	@echo "════════════════════════════════"
	@echo "  make up          Démarre Specula (Suricata + Backend + Frontend)"
	@echo "  make up-wazuh    Démarre tout + stack Wazuh + agent hôte"
	@echo "  make down        Arrête et supprime les conteneurs"
	@echo "  make rebuild     Reconstruit les images et redémarre"
	@echo "  make logs        Suit les logs en temps réel"
	@echo "  make ps          Liste les services actifs"
	@echo "  make wazuh-certs Génère les certificats Wazuh (requis avant up-wazuh)"
	@echo ""
	@echo "Accès après démarrage :"
	@echo "  Console   : http://localhost:5173"
	@echo "  API Docs  : http://localhost:8000/docs"
	@echo ""

# ─── Création .env ─────────────────────────────────────────────
.env:
	@if [ -f .env.example ]; then \
		cp .env.example .env; \
		echo "[specula] .env créé depuis .env.example"; \
	else \
		echo "[specula] ERREUR: .env.example manquant"; exit 1; \
	fi

# ─── Macro : détection interface + démarrage ───────────────────
# Tout dans un seul shell pour que SURICATA_INTERFACE se propage.
define _start
	set -a; . ./$(ENV_FILE); set +a; \
	if [ -z "$${SURICATA_INTERFACE:-}" ]; then \
		SURICATA_INTERFACE=$$(ip -o link show \
			| awk -F': ' '{print $$2}' \
			| sed 's/@.*//' \
			| grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|tun|tap|wg[0-9]*|zt)' \
			| grep -E '^(eth|en|ens|enp|eno|wlan|wl)' \
			| head -n1 || true); \
		if [ -z "$$SURICATA_INTERFACE" ]; then \
			echo "[specula] ERREUR: interface réseau non détectée."; \
			echo "          Ajoutez SURICATA_INTERFACE=<interface> dans .env"; \
			exit 1; \
		fi; \
		echo "[specula] Interface auto-détectée : $$SURICATA_INTERFACE"; \
	else \
		echo "[specula] Interface : $$SURICATA_INTERFACE"; \
	fi; \
	mkdir -p runtime/logs/suricata; \
	SURICATA_INTERFACE=$$SURICATA_INTERFACE $(COMPOSE) --env-file $(ENV_FILE)
endef

# ─── Démarrage ─────────────────────────────────────────────────
up: .env
	@$(_start) up -d --remove-orphans
	@echo ""
	@echo "════════════════════════════════════"
	@echo "  Console : http://localhost:5173"
	@echo "  API     : http://localhost:8000/docs"
	@echo "════════════════════════════════════"

up-wazuh: .env wazuh-certs
	@sed -i 's/SPECULA_ENABLE_WAZUH=false/SPECULA_ENABLE_WAZUH=true/' $(ENV_FILE) 2>/dev/null || true
	@$(_start) --profile wazuh up -d --remove-orphans
	@echo ""
	@echo "════════════════════════════════════"
	@echo "  Console       : http://localhost:5173"
	@echo "  API           : http://localhost:8000/docs"
	@echo "  Wazuh Manager : https://localhost:55000"
	@echo "  Wazuh Indexer : https://localhost:9200"
	@echo "════════════════════════════════════"

# ─── Reconstruction ────────────────────────────────────────────
rebuild: .env
	@$(_start) up -d --remove-orphans --build

# ─── Arrêt ─────────────────────────────────────────────────────
down:
	@echo "[specula] Arrêt de la stack..."
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh down --remove-orphans

# ─── Reset complet ─────────────────────────────────────────────
reset:
	@echo "[specula] Reset complet (volumes inclus)..."
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh down -v --remove-orphans
	@$(MAKE) up

# ─── Logs ──────────────────────────────────────────────────────
logs:
	@$(COMPOSE) --env-file $(ENV_FILE) logs -f

# ─── Statut ────────────────────────────────────────────────────
ps:
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh ps

# ─── Certificats Wazuh ─────────────────────────────────────────
wazuh-certs:
	@if [ -f runtime/wazuh/certs/root-ca.pem ] && \
	    [ -f runtime/wazuh/certs/wazuh-indexer.pem ] && \
	    [ -f runtime/wazuh/certs/admin.pem ]; then \
		echo "[specula] Certificats Wazuh déjà présents."; \
	else \
		echo "[specula] Génération des certificats Wazuh (~30s)..."; \
		mkdir -p runtime/wazuh/certs; \
		docker compose -f deploy/docker/core/wazuh/generate-certs.yml run --rm generator; \
		echo "[specula] Certificats générés."; \
	fi
