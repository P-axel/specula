COMPOSE  = docker compose -f deploy/docker/core/docker-compose.yml
ENV_FILE = .env

.PHONY: up down reset rebuild logs logs-core logs-suricata logs-wazuh ps open check wazuh-certs agent-install agent-status versions-check versions-update help

# ─── Aide ──────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  Specula — Commandes disponibles"
	@echo "  ════════════════════════════════════════════"
	@echo ""
	@echo "  Démarrage"
	@echo "    make check           Vérifie l'environnement (Docker, ports, disque)"
	@echo "    make up              Démarre Specula (choix interactif)"
	@echo "    make open            Ouvre la console dans le navigateur"
	@echo "    make down            Arrête et supprime les conteneurs"
	@echo "    make rebuild         Reconstruit les images et redémarre"
	@echo ""
	@echo "  Logs (filtrés)"
	@echo "    make logs            Tous les services"
	@echo "    make logs-core       Backend + Console uniquement"
	@echo "    make logs-suricata   IDS réseau uniquement"
	@echo "    make logs-wazuh      Stack Wazuh uniquement"
	@echo ""
	@echo "  Agents Wazuh"
	@echo "    make agent-install   Installe un agent natif sur cette machine (sudo)"
	@echo "    make agent-status    Vérifie la connexion de l'agent au manager"
	@echo ""
	@echo "  Mises à jour"
	@echo "    make versions-check  Affiche les versions en cours vs. latest"
	@echo "    make versions-update Applique les dernières versions stables dans .env"
	@echo ""
	@echo "  Accès"
	@echo "    Console   : http://localhost:5173"
	@echo "    API Docs  : http://localhost:8000/docs"
	@echo ""

# ─── Vérification environnement ────────────────────────────────
check:
	@set -e; \
	OK=1; \
	echo ""; \
	echo "  Specula — Vérification de l'environnement"; \
	echo "  ══════════════════════════════════════════"; \
	echo ""; \
	echo "  Prérequis système :"; \
	if docker info >/dev/null 2>&1; then \
		echo "  [OK] Docker en cours d'exécution"; \
	else \
		echo "  [KO] Docker inaccessible — sudo systemctl start docker"; \
		OK=0; \
	fi; \
	if docker compose version >/dev/null 2>&1; then \
		echo "  [OK] Docker Compose v2 disponible"; \
	else \
		echo "  [KO] Docker Compose v2 introuvable"; \
		OK=0; \
	fi; \
	if command -v curl >/dev/null 2>&1; then \
		echo "  [OK] curl disponible"; \
	else \
		echo "  [KO] curl manquant — sudo apt-get install curl"; \
		OK=0; \
	fi; \
	DISK_MB=$$(df -m . | awk 'NR==2 {print $$4}'); \
	if [ "$$DISK_MB" -ge 5120 ]; then \
		echo "  [OK] Espace disque : $$((DISK_MB / 1024)) Go disponible"; \
	else \
		echo "  [KO] Espace insuffisant : $$DISK_MB Mo (5 Go requis pour Wazuh)"; \
		OK=0; \
	fi; \
	echo ""; \
	echo "  Ports réseau :"; \
	for PORT in 5173 8000 1514 1515 9200; do \
		if ss -tlnp 2>/dev/null | grep -q ":$$PORT " || \
		   lsof -i :$$PORT >/dev/null 2>&1; then \
			echo "  [KO] Port $$PORT déjà utilisé"; \
			OK=0; \
		else \
			echo "  [OK] Port $$PORT disponible"; \
		fi; \
	done; \
	echo ""; \
	if docker ps --format '{{.Names}}' 2>/dev/null | grep -q 'specula-backend'; then \
		echo "  Services Specula (démarrés) :"; \
		if curl -sf http://localhost:8000/health >/dev/null 2>&1; then \
			echo "  [OK] API backend  — http://localhost:8000/docs"; \
		else \
			echo "  [--] API backend  — pas encore prête"; \
		fi; \
		if curl -sf http://localhost:5173 >/dev/null 2>&1; then \
			echo "  [OK] Console      — http://localhost:5173"; \
		else \
			echo "  [--] Console      — pas encore prête"; \
		fi; \
		if docker ps --format '{{.Names}}' | grep -q 'wazuh-manager'; then \
			if curl -sk https://localhost:55000 >/dev/null 2>&1; then \
				echo "  [OK] Wazuh Manager — https://localhost:55000"; \
			else \
				echo "  [--] Wazuh Manager — en démarrage"; \
			fi; \
		fi; \
		echo ""; \
	fi; \
	if [ "$$OK" = "1" ]; then \
		echo "  Tout est prêt. Lance : make up"; \
	else \
		echo "  Corrige les points [KO] avant de continuer."; \
	fi; \
	echo ""

# ─── Ouvrir la console ──────────────────────────────────────────
open:
	@URL="http://localhost:5173"; \
	if curl -sf "$$URL" >/dev/null 2>&1; then \
		xdg-open "$$URL" 2>/dev/null || open "$$URL" 2>/dev/null || \
		echo "[specula] Ouvre manuellement : $$URL"; \
	else \
		echo "[specula] La console n'est pas encore démarrée."; \
		echo "          Lance d'abord : make up"; \
	fi

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
	@echo "  [3] Stack complète + IA — Suricata + Wazuh + Ollama (analyse IA locale)"
	@echo ""
	@printf "  Votre choix [1/2/3] : "; \
	read CHOICE; \
	set -a; . ./$(ENV_FILE); set +a; \
	$(call _detect_iface); \
	mkdir -p runtime/logs/suricata; \
	if [ "$$CHOICE" = "2" ]; then \
		$(MAKE) --no-print-directory _start-wazuh SURICATA_INTERFACE=$$SURICATA_INTERFACE; \
	elif [ "$$CHOICE" = "3" ]; then \
		$(MAKE) --no-print-directory _start-ai SURICATA_INTERFACE=$$SURICATA_INTERFACE; \
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
	@echo "[specula] Attente du démarrage de l'indexer Wazuh..."; \
	n=0; while [ $$n -lt 40 ]; do \
		if curl -sk https://localhost:9200 >/dev/null 2>&1; then \
			echo "[specula] Indexer prêt."; break; \
		fi; \
		printf "."; sleep 3; n=$$((n+1)); \
	done; \
	if [ $$n -eq 40 ]; then \
		echo ""; echo "[specula] WARN: timeout — tentative d'initialisation quand même..."; \
	else \
		echo ""; \
	fi
	@$(MAKE) --no-print-directory wazuh-security-init
	@$(MAKE) --no-print-directory wazuh-enable-vuln
	@echo ""
	@echo "  ════════════════════════════════════"
	@echo "  Console       : http://localhost:5173"
	@echo "  API           : http://localhost:8000/docs"
	@echo "  Wazuh Manager : https://localhost:55000"
	@echo "  ════════════════════════════════════"
	@echo ""

# ─── Démarrage stack complète + IA ────────────────────────────
_start-ai: _start-wazuh
	@set -a; . ./$(ENV_FILE); set +a; \
	sed -i 's/SPECULA_ENABLE_AI=false/SPECULA_ENABLE_AI=true/' $(ENV_FILE) 2>/dev/null || true; \
	SURICATA_INTERFACE=${SURICATA_INTERFACE} $(COMPOSE) --env-file $(ENV_FILE) --profile wazuh --profile ai up -d --remove-orphans
	@echo "[specula] Téléchargement du modèle Ollama (première fois : ~5GB)..."
	@set -a; . ./$(ENV_FILE); set +a; \
	docker exec specula-ollama ollama pull $${OLLAMA_MODEL:-llama3.1:8b} 2>&1 | tail -3 || true
	@echo ""
	@echo "  ════════════════════════════════════"
	@echo "  Console       : http://localhost:5173"
	@echo "  API           : http://localhost:8000/docs"
	@echo "  Ollama        : http://localhost:11434"
	@echo "  ════════════════════════════════════"
	@echo ""

# ─── Init sécurité indexer Wazuh (securityadmin) ───────────────
# Le hash est généré dynamiquement dans le container depuis WAZUH_INDEXER_PASSWORD
# pour éviter les problèmes d'inode avec les fichiers bind-montés en :ro.
wazuh-security-init:
	@echo "[specula] Application de la configuration de sécurité OpenSearch..."
	@set -a; . ./$(ENV_FILE); set +a; \
	INDEXER_PWD=$${WAZUH_INDEXER_PASSWORD:-SecretPassword}; \
	docker exec -u root -e INDEXER_PWD="$$INDEXER_PWD" wazuh-indexer bash -c ' \
		export JAVA_HOME=/usr/share/wazuh-indexer/jdk; \
		CERTS=/usr/share/wazuh-indexer/config/certs; \
		HASH=$$( /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh \
		  -p "$$INDEXER_PWD" 2>/dev/null | grep -v "WARNING\|^\*" | tail -1 ); \
		printf "%s\n" "---" "_meta:" "  type: \"internalusers\"" "  config_version: 2" \
		  "admin:" "  hash: \"$$HASH\"" "  reserved: true" "  backend_roles:" \
		  "    - \"admin\"" "  description: \"Wazuh indexer admin\"" \
		  "kibanaserver:" \
		  "  hash: \"\$$2a\$$12\$$4AcgAt3xwOWadA5s5blL6ev39OXDNhmOesEoo33eZtrq2N0YrU3H.\"" \
		  "  reserved: true" "  description: \"OpenSearch Dashboards user\"" \
		  > /tmp/internal_users.yml; \
		/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
		  -f /tmp/internal_users.yml -t internalusers -icl -nhnv \
		  -cacert $$CERTS/root-ca.pem \
		  -cert $$CERTS/admin.pem \
		  -key $$CERTS/admin-key.pem \
		  -h localhost -p 9200 2>&1 | grep -E "SUCC:|Done"' || true
	@echo "[specula] Sécurité OpenSearch initialisée."

# ─── Détection de vulnérabilités Wazuh ─────────────────────────
# Active le vulnerability-detector dans le manager (Debian 12 bookworm).
# Les packages remontés par syscollector (agent) sont croisés avec les CVE.
wazuh-enable-vuln:
	@echo "[specula] Activation de la détection de vulnérabilités Wazuh (Debian bookworm)..."
	@docker exec -u root wazuh-manager bash -c '\
		conf=/var/ossec/etc/ossec.conf; \
		sed -i "/<vulnerability-detector>/,/<\/vulnerability-detector>/ { \
		  s|<enabled>no</enabled>|<enabled>yes</enabled>| \
		}" "$$conf"; \
		sed -i "/<provider name=\"debian\">/,/<\/provider>/ { \
		  s|<enabled>no</enabled>|<enabled>yes</enabled>| \
		}" "$$conf"; \
		grep -q "<os>bookworm</os>" "$$conf" || \
		  sed -i "/<provider name=\"debian\">/,/<\/provider>/ { \
		    s|<os>buster</os>|<os>buster</os>\n      <os>bookworm</os>| \
		  }" "$$conf"; \
		echo "[specula] ossec.conf mis à jour"; \
		grep -A3 "<vulnerability-detector>" "$$conf" | head -4'
	@docker restart wazuh-manager > /dev/null
	@printf "[specula] Manager redémarré, attente du démarrage des services..."; \
	for i in $$(seq 1 20); do \
		docker exec wazuh-manager /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-apid is running" && break; \
		printf "."; sleep 2; \
	done; echo ""
	@docker exec wazuh-manager /var/ossec/bin/wazuh-control start > /dev/null 2>&1 || true
	@echo "[specula] Wazuh opérationnel — premier scan de vulnérabilités dans ~5 min"

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

logs-core:
	@$(COMPOSE) --env-file $(ENV_FILE) logs -f specula-backend specula-console

logs-suricata:
	@$(COMPOSE) --env-file $(ENV_FILE) logs -f specula-suricata

logs-wazuh:
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh logs -f wazuh-manager wazuh-indexer wazuh-agent-host

# ─── Statut ────────────────────────────────────────────────────
ps:
	@$(COMPOSE) --env-file $(ENV_FILE) --profile wazuh ps

# ─── Versions (lues depuis .env si disponible) ─────────────────────
-include .env
WAZUH_VERSION   ?= 4.14.4
SURICATA_VERSION ?= latest

# ─── Vérification des versions disponibles ─────────────────────────
versions-check:
	@echo ""
	@echo "  Specula — Versions en cours"
	@echo "  ══════════════════════════════════════════"
	@echo ""
	@echo "  Wazuh :"
	@printf "    En cours   : $(WAZUH_VERSION)\n"
	@LATEST=$$(curl -s https://api.github.com/repos/wazuh/wazuh/releases/latest \
		| grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//'); \
	if [ "$$LATEST" = "$(WAZUH_VERSION)" ]; then \
		printf "    Latest     : $$LATEST  [OK]\n"; \
	else \
		printf "    Latest     : $$LATEST  [MISE A JOUR DISPONIBLE]\n"; \
		printf "    → make versions-update pour mettre à jour\n"; \
	fi
	@echo ""
	@echo "  Agent natif installé :"
	@if command -v /var/ossec/bin/wazuh-agentd >/dev/null 2>&1; then \
		/var/ossec/bin/wazuh-agentd --version 2>&1 | grep "Wazuh" | head -1 | sed 's/^/    /'; \
	elif dpkg -s wazuh-agent >/dev/null 2>&1; then \
		dpkg -s wazuh-agent | grep Version | sed 's/^/    /'; \
	else \
		echo "    Non installé sur l'hôte"; \
	fi
	@echo ""

# ─── Mise à jour automatique de la version dans .env ───────────────
versions-update:
	@echo "[specula] Récupération de la dernière version Wazuh..."
	@LATEST=$$(curl -s https://api.github.com/repos/wazuh/wazuh/releases/latest \
		| grep '"tag_name"' | cut -d'"' -f4 | sed 's/^v//'); \
	if [ -z "$$LATEST" ]; then \
		echo "[specula] ERREUR : impossible de contacter l'API GitHub"; exit 1; \
	fi; \
	CURRENT=$$(grep '^WAZUH_VERSION=' .env 2>/dev/null | cut -d= -f2 || echo "$(WAZUH_VERSION)"); \
	if [ "$$LATEST" = "$$CURRENT" ]; then \
		echo "[specula] Wazuh déjà à jour : $$CURRENT"; \
	else \
		echo "[specula] Mise à jour Wazuh : $$CURRENT → $$LATEST"; \
		if grep -q '^WAZUH_VERSION=' .env 2>/dev/null; then \
			sed -i "s/^WAZUH_VERSION=.*/WAZUH_VERSION=$$LATEST/" .env; \
		else \
			echo "WAZUH_VERSION=$$LATEST" >> .env; \
		fi; \
		echo "[specula] .env mis à jour. Lance 'make rebuild' pour appliquer."; \
	fi

# ─── Agent Wazuh natif sur la machine hôte ─────────────────────────
# Installe le paquet wazuh-agent sur le système hôte (pas dans Docker)
# et le connecte au wazuh-manager exposé sur localhost:1514/1515.
# Nécessite sudo. Version lue depuis .env (WAZUH_VERSION).
WAZUH_AGENT_NAME ?= $(shell hostname)

agent-install:
	@set -e; \
	echo ""; \
	echo "  ╔═══════════════════════════════════════╗"; \
	echo "  ║    Specula — Installation agent       ║"; \
	echo "  ╚═══════════════════════════════════════╝"; \
	echo ""; \
	if systemctl is-active --quiet wazuh-agent 2>/dev/null; then \
		echo "[specula] L'agent Wazuh est déjà installé et actif."; \
		echo "          Pour vérifier sa connexion : make agent-status"; \
		exit 0; \
	fi; \
	if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^wazuh-manager$$'; then \
		echo "[specula] ERREUR : le manager Wazuh n'est pas démarré."; \
		echo "          Lance d'abord :  make up  (puis choisir l'option 2)"; \
		echo "          Ensuite relance : make agent-install"; \
		exit 1; \
	fi; \
	if ! command -v apt-get >/dev/null 2>&1; then \
		echo "[specula] ERREUR : apt-get introuvable."; \
		echo "          L'installation automatique nécessite Debian ou Ubuntu."; \
		echo "          Voir le README pour l'installation manuelle."; \
		exit 1; \
	fi; \
	echo "[specula] Ajout du dépôt Wazuh..."; \
	curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
		| sudo gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg; \
	echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg arch=amd64] https://packages.wazuh.com/4.x/apt/ stable main" \
		| sudo tee /etc/apt/sources.list.d/wazuh.list > /dev/null; \
	echo "[specula] Mise à jour des paquets..."; \
	sudo apt-get update; \
	echo "[specula] Installation de wazuh-agent $(WAZUH_VERSION)..."; \
	sudo WAZUH_MANAGER="127.0.0.1" \
	     WAZUH_AGENT_NAME="$(WAZUH_AGENT_NAME)" \
	     apt-get install -y wazuh-agent=$(WAZUH_VERSION)-1; \
	sudo systemctl daemon-reload; \
	sudo systemctl enable --now wazuh-agent; \
	echo "[specula] Agent natif démarré, attente de l'enrôlement..."; \
	sleep 5; \
	STALE=$$(docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null \
		| grep "specula-host" | grep "Disconnected" \
		| grep -o 'ID: [0-9]*' | awk '{print $$2}'); \
	if [ -n "$$STALE" ]; then \
		echo "[specula] Nettoyage de l'agent container bloqué (ID $$STALE)..."; \
		printf "R\n$$STALE\ny\nQ\n" \
			| docker exec -i wazuh-manager /var/ossec/bin/manage_agents >/dev/null 2>&1 || true; \
		docker restart wazuh-agent-host >/dev/null 2>&1 || true; \
		sleep 5; \
	fi; \
	echo ""; \
	echo "  ════════════════════════════════════════════════"; \
	echo "  Agent natif  : $(WAZUH_AGENT_NAME) ($$(systemctl is-active wazuh-agent))"; \
	echo "  Manager      : 127.0.0.1:1514"; \
	echo ""; \
	echo "  Agents connectés au manager :"; \
	docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null \
		| grep -v "^$$" | grep -v "agentless" \
		| sed 's/^/    /'; \
	echo "  ════════════════════════════════════════════════"; \
	echo ""

agent-status:
	@echo "[specula] Statut de l'agent Wazuh local :"
	@systemctl is-active wazuh-agent 2>/dev/null \
		&& echo "  Service : actif" \
		|| echo "  Service : inactif (agent non installé ?)"
	@echo ""
	@echo "[specula] Agents connectés au manager :"
	@docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>/dev/null \
		|| echo "  Le manager Wazuh n'est pas démarré (make up -> option 2)"
	@echo ""

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
