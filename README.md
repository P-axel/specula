# Specula — Plateforme SOC modulaire

*par [Pierre-Axel Annonier](https://p-axel.github.io/)*

Specula est une plateforme de détection et d'analyse d'événements de sécurité, pensée pour construire un SOC **plus lisible, plus exploitable et plus accessible**.

> **Statut : MVP fonctionnel — en développement actif.**

---

## Pourquoi Specula ?

Mettre en place un SOC est souvent complexe, lourd et difficile à exploiter. Specula propose une approche différente :

- Se concentrer sur les bons événements
- Corréler les signaux utiles automatiquement
- Rendre l'analyse compréhensible sans noyer l'analyste
- Structurer la détection plutôt que l'empiler

**Specula n'est pas un collecteur de logs. C'est un moteur de corrélation et d'analyse.**

---

## Architecture

```
Suricata (réseau)  ──┐
                     ├──▶ Normalizer ──▶ Correlator ──▶ FastAPI ──▶ React Console
Wazuh (endpoint)   ──┘         (optionnel)
```

- **Suricata** — IDS réseau en temps réel, actif par défaut
- **Wazuh** — supervision endpoint (logs système, processus, fichiers), optionnel
- **specula-core** — backend FastAPI : ingestion, normalisation, corrélation d'incidents
- **specula-console** — interface React pour analyser les incidents

---

## Prérequis

- Docker + Docker Compose (v2)
- `make`
- Linux (testé sur Debian/Ubuntu)

```bash
docker ps              # vérifier que Docker tourne
docker compose version
```

Si Docker n'est pas accessible :

```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

---

## Installation

### 1. Cloner le projet

```bash
git clone https://github.com/P-axel/specula.git
cd specula
```

### 2. Démarrer

```bash
make up
```

C'est tout. Le Makefile crée le `.env` si absent, détecte l'interface réseau automatiquement et construit les images Docker.

Si l'auto-détection de l'interface échoue, ajoutez dans `.env` :

```bash
SURICATA_INTERFACE=eth0   # ip route pour identifier la vôtre
```

---

## Accès

| Service | URL |
|---|---|
| Console Specula | http://localhost:5173 |
| API (Swagger) | http://localhost:8000/docs |

---

## Mode Wazuh (optionnel)

Pour activer la supervision endpoint avec un agent Wazuh sur la machine hôte :

```bash
make up-wazuh
```

Démarre en plus :
- `wazuh-manager` — serveur Wazuh (port 55000)
- `wazuh-indexer` — stockage OpenSearch (port 9200)
- `wazuh-agent` — agent surveillant les logs système du host (`/var/log`, `/etc`, `/proc`)

> La première fois, les certificats TLS Wazuh sont générés automatiquement (~30s).

---

## Commandes disponibles

```bash
make up          # Suricata + Backend + Frontend
make up-wazuh    # + Stack Wazuh + agent hôte
make rebuild     # Reconstruire les images et redémarrer
make down        # Arrêter tous les services
make logs        # Suivre les logs en temps réel
make ps          # Lister les services actifs
```

---

## Règles de détection réseau

Suricata est configuré avec des règles couvrant les menaces les plus courantes :

| Catégorie | Exemples |
|---|---|
| Scans de ports | TCP SYN sweep, Nmap OS detection, UDP sweep |
| Brute force | SSH (5+ tentatives / 60s) |
| DNS suspect | Requêtes longues (exfiltration), volume élevé (tunneling) |
| C2 / backdoors | Ports 4444, 1337, 31337, 6667 (IRC) |
| Attaques web | SQL injection, path traversal, upload PHP |
| Protocoles non chiffrés | FTP, Telnet |
| Flood | ICMP flood (50+ pings / 5s) |

Ces alertes sont ingérées et corrélées automatiquement en incidents dans la console.

---

## Dépannage

**Interface réseau non détectée**

```bash
ip route   # identifier l'interface (ex: eth0, wlan0, enp3s0)
```

Puis dans `.env` : `SURICATA_INTERFACE=eth0`

**Ports déjà utilisés**

```bash
lsof -i :8000
lsof -i :5173
```

**Voir les logs**

```bash
make logs
# ou directement
docker compose -f deploy/docker/core/docker-compose.yml logs -f
```

---

## État du projet

| Brique | État |
|---|---|
| Suricata IDS + corrélation d'incidents | Fonctionnel |
| Ingestion Wazuh (manager + indexer) | Fonctionnel |
| Agent Wazuh sur hôte | Fonctionnel |
| Console React (incidents, assets, dashboard) | Fonctionnel |
| Modularité des connecteurs | En cours |
| Tests automatisés | Partiel |

---

## À propos

Pierre-Axel Annonier — Ingénieur cybersécurité

- https://p-axel.github.io/
- https://www.linkedin.com/in/pierre-axel-annonier

---

## Licence

MIT
