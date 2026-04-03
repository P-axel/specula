COMPOSE_CORE = docker compose -f deploy/docker/core/docker-compose.yml

.PHONY: help core core-up core-down core-logs core-ps core-rebuild logs-backend logs-frontend logs-suricata

help:
	@echo "Targets disponibles :"
	@echo "  make core          -> affiche les commandes core"
	@echo "  make core-up       -> démarre la stack core"
	@echo "  make core-down     -> arrête la stack core"
	@echo "  make core-ps       -> affiche l'état de la stack core"
	@echo "  make core-logs     -> suit tous les logs core"
	@echo "  make core-rebuild  -> rebuild + restart du core"
	@echo "  make logs-backend  -> logs backend"
	@echo "  make logs-frontend -> logs frontend"
	@echo "  make logs-suricata -> logs suricata"

core:
	@echo "Specula core commands:"
	@echo "  make core-up"
	@echo "  make core-down"
	@echo "  make core-logs"
	@echo "  make core-ps"
	@echo "  make core-rebuild"

core-up:
	$(COMPOSE_CORE) up -d

core-down:
	$(COMPOSE_CORE) down

core-ps:
	$(COMPOSE_CORE) ps

core-logs:
	$(COMPOSE_CORE) logs -f

core-rebuild:
	$(COMPOSE_CORE) down
	$(COMPOSE_CORE) up -d --build

logs-backend:
	$(COMPOSE_CORE) logs -f specula-backend

logs-frontend:
	$(COMPOSE_CORE) logs -f specula-frontend

logs-suricata:
	$(COMPOSE_CORE) logs -f specula-suricata
