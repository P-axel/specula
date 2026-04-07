COMPOSE  = docker compose -f deploy/docker/core/docker-compose.yml
ENV_FILE = .env

.PHONY: up up-wazuh down reset rebuild logs ps wazuh-certs help

# ─── Aide ──────────────────────────────────────────────────────
help:
	@echo ""
	@echo "Specula — Commandes disponibles"
	@echo "════════════════════════════════"
	@echo "  make up       Démarre Specula (choix interactif des modules)"
	@echo "  make down     Arrête et supprime les conteneurs"
	@echo "  make rebuild  Reconstruit les images et redémarre"
	@echo "  make logs     Suit les logs en temps réel"
	@echo "  make ps       Liste les services actifs"
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

# ─── Macro : détection interface réseau ────────────────────────
# Tout dans un seul shell pour que SURICATA_INTERFACE se propage.
define _detect_iface
	if [ -z "$${SURICATA_INTERFACE:-}" ]; then \
		SURICATA_INTERFACE=$$(ip -o link show \
			| awk -F': ' '{print $$2}' \
			| sed 's/@.*//' \
			| grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|tun|tap|wg[0-9]*|zt)' \
			| grep -E '^(eth|en|ens|enp|eno|wlan|wl|enx)' \
			| head -n1 || true); \
		if [ -z "$$SURICATA_INTERFACE" ]; then \
			echo "[specula] ERREUR: interface réseau non détectée."; \
			echo "          Ajoutez SURICATA_INTERFACE=<interface> dans .env"; \
			exit 1; \
		fi; \
		echo "[specula] Interface auto-détectée : $$SURICATA_INTERFACE"; \
	else \
		echo "[specula] Interface : $$SURICATA_INTERFACE"; \
	fi
endef

# ─── Démarrage interactif ──────────────────────────────────────
up: .env
	@echo ""
	@echo "  ╔═══════════════════════════════════════╗"
	@echo "  ║        Specula — Démarrage            ║"
	@echo "  ╚═══════════════════════════════════════╝"
	@echo ""
	@echo "  [1] Réseau uniquement   — Suricata (IDS réseau)"
	@echo "  [2] Stack complète      — Suricata + Wazuh (réseau + endpoints)"
	@echo ""
	@printf "  Votre choix [1/2] : "; \
	read CHOICE; \
	set -a; . ./$(ENV_FILE); set +a; \
	$(call _detect_iface); \
	mkdir -p runtime/logs/suricata; \
	if [ "$$CHOICE" = "2" ]; then \
		$(MAKE) --no-print-directory _start-wazuh SURICATA_INTERFACE=$$SURICATA_INTERFACE; \
	else \
		$(MAKE) --no-print-directory _start-base SURICATA_INTERFACE=$$SURICATA_INTERFACE; \
	fi

# ─── Démarrage stack de base ───────────────────────────────────
_start-base:
	@set -a; . ./$(ENV_FILE); set +a; \
	sed -i 's/SPECULA_ENABLE_WAZUH=true/SPECULA_ENABLE_WAZUH=false/' $(ENV_FILE) 2>/dev/null || true; \
	SURICATA_INTERFACE=${SURICATA_INTERFACE} $(COMPOSE) --env-file $(ENV_FILE) up -d --remove-orphans
	@echo ""
	@echo "  ════════════════════════════════════"
	@echo "  Console : http://localhost:5173"
	@echo "  API     : http://localhost:8000/docs"
	@echo "  ════════════════════════════════════"
	@echo ""

# ─── Démarrage stack complète avec Wazuh ───────────────────────
_start-wazuh: wazuh-certs
	@set -a; . ./$(ENV_FILE); set +a; \
	sed -i 's/SPECULA_ENABLE_WAZUH=false/SPECULA_ENABLE_WAZUH=true/' $(ENV_FILE) 2>/dev/null || true; \
	SURICATA_INTERFACE=${SURICATA_INTERFACE} $(COMPOSE) --env-file $(ENV_FILE) --profile wazuh up -d --remove-orphans
	@echo "[specula] Initialisation sécurité Wazuh indexer (~15s)..."
	@sleep 15
	@$(MAKE) --no-print-directory wazuh-security-init
	@echo ""
	@echo "  ════════════════════════════════════"
	@echo "  Console       : http://localhost:5173"
	@echo "  API           : http://localhost:8000/docs"
	@echo "  Wazuh Manager : https://localhost:55000"
	@echo "  ════════════════════════════════════"
	@echo ""

# ─── Init sécurité indexer Wazuh (securityadmin) ───────────────
wazuh-security-init:
	@echo "[specula] Application de la configuration de sécurité OpenSearch..."
	@docker exec -u root wazuh-indexer bash -c "\
		export JAVA_HOME=/usr/share/wazuh-indexer/jdk; \
		cp /usr/share/wazuh-indexer/certs/admin.key /tmp/admin-key-pkcs8.pem 2>/dev/null || \
		cp /usr/share/wazuh-indexer/certs/admin-key.pem /tmp/admin-key-pkcs8.pem 2>/dev/null || true; \
		/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
		  -cd /usr/share/wazuh-indexer/opensearch-security/ \
		  -icl -nhnv \
		  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
		  -cert /usr/share/wazuh-indexer/certs/admin.pem \
		  -key /tmp/admin-key-pkcs8.pem \
		  -h localhost -p 9200 2>&1 | grep -E 'SUCC:|ERR:|Done'" || \
	echo "[specula] WARN: securityadmin a échoué — credentials indexer peut-être déjà configurés."

# ─── Reconstruction ────────────────────────────────────────────
rebuild: .env
	@set -a; . ./$(ENV_FILE); set +a; \
	if [ -z "$${SURICATA_INTERFACE:-}" ]; then \
		SURICATA_INTERFACE=$$(ip -o link show \
			| awk -F': ' '{print $$2}' \
			| sed 's/@.*//' \
			| grep -Ev '^(lo|docker[0-9]*|br-|veth|virbr|tun|tap|wg[0-9]*|zt)' \
			| grep -E '^(eth|en|ens|enp|eno|wlan|wl|enx)' \
			| head -n1 || true); \
	fi; \
	SURICATA_INTERFACE=$$SURICATA_INTERFACE $(COMPOSE) --env-file $(ENV_FILE) --profile wazuh up -d --remove-orphans --build

# ─── Arrêt ─────────────────────────────────────────────────────
down:
	@echo "[specula] Arrêt de la stack..."
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh down --remove-orphans
	@echo "[specula] Stack arrêtée."

# ─── Reset complet ─────────────────────────────────────────────
reset:
	@echo "[specula] Reset complet (volumes inclus)..."
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh down -v --remove-orphans
	@$(MAKE) up

# ─── Logs ──────────────────────────────────────────────────────
logs:
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh logs -f

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
		chmod 777 runtime/wazuh/certs; \
		docker run --rm \
			-v "$$(pwd)/deploy/docker/core/wazuh/config.yml:/config/certs.yml:ro" \
			-v "$$(pwd)/runtime/wazuh/certs:/certificates" \
			wazuh/wazuh-certs-generator:0.0.2; \
		echo "[specula] Certificats générés."; \
	fi
