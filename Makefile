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

# ─── Préparation ───────────────────────────────────────────────
.env:
	@if [ -f .env.example ]; then \
		cp .env.example .env; \
		echo "[specula] .env créé depuis .env.example"; \
	else \
		echo "[specula] ERREUR: .env.example manquant"; exit 1; \
	fi

_detect-interface:
	@if [ -z "$${SURICATA_INTERFACE:-}" ]; then \
		DETECTED=$$(ip -o link show \
			| awk -F': ' '{print $$2}' \
			| sed 's/@.*//' \
			| grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|tun|tap|wg[0-9]*|zt)' \
			| grep -E '^(eth|en|ens|enp|eno|wlan|wl)' \
			| head -n1 || true); \
		if [ -n "$$DETECTED" ]; then \
			echo "[specula] Interface Suricata auto-détectée : $$DETECTED"; \
			export SURICATA_INTERFACE=$$DETECTED; \
		else \
			echo "[specula] ERREUR: impossible de détecter l'interface. Ajoutez SURICATA_INTERFACE dans .env"; \
			exit 1; \
		fi; \
	fi

_runtime-dirs:
	@mkdir -p runtime/logs/suricata

# ─── Démarrage ─────────────────────────────────────────────────
up: .env _detect-interface _runtime-dirs
	@echo "[specula] Démarrage de la stack..."
	@set -a; . ./$(ENV_FILE); set +a; \
	$(COMPOSE) --env-file $(ENV_FILE) up -d --remove-orphans
	@echo ""
	@echo "════════════════════════════════════"
	@echo "  Console : http://localhost:5173"
	@echo "  API     : http://localhost:8000/docs"
	@echo "════════════════════════════════════"

up-wazuh: .env _detect-interface _runtime-dirs wazuh-certs
	@echo "[specula] Activation de Wazuh dans .env..."
	@sed -i 's/SPECULA_ENABLE_WAZUH=false/SPECULA_ENABLE_WAZUH=true/' $(ENV_FILE) 2>/dev/null || true
	@echo "[specula] Démarrage de la stack avec Wazuh..."
	@set -a; . ./$(ENV_FILE); set +a; \
	$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh up -d --remove-orphans
	@echo ""
	@echo "════════════════════════════════════"
	@echo "  Console       : http://localhost:5173"
	@echo "  API           : http://localhost:8000/docs"
	@echo "  Wazuh Manager : https://localhost:55000"
	@echo "  Wazuh Indexer : https://localhost:9200"
	@echo "════════════════════════════════════"

# ─── Reconstruction ────────────────────────────────────────────
rebuild: .env _detect-interface _runtime-dirs
	@echo "[specula] Reconstruction des images..."
	@set -a; . ./$(ENV_FILE); set +a; \
	$(COMPOSE) --env-file $(ENV_FILE) up -d --remove-orphans --build

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
