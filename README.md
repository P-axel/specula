# Specula — Plateforme SOC modulaire

*par [Pierre-Axel Annonier](https://p-axel.github.io/)*

Specula est une plateforme de détection et d'analyse d'événements de sécurité, pensée pour construire un SOC **plus lisible, plus exploitable et plus accessible**.

> **Statut : MVP fonctionnel — en développement actif.**

---


![alt text](<Copie d'écran_2021_145653.png>)



![alt text](<Copie d'écran_20260408_145622.png>)






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

### 2. Vérifier l'environnement (optionnel mais recommandé)

```bash
make check
```

Vérifie que Docker tourne, que les ports sont libres et que l'espace disque est suffisant. Corrige les points `[KO]` avant de continuer.

### 3. Démarrer

```bash
make up
```

Le Makefile crée le `.env` si absent, détecte l'interface réseau automatiquement et construit les images Docker.

### 4. Ouvrir la console

```bash
make open   # ouvre http://localhost:5173 dans le navigateur
```

Si l'auto-détection de l'interface réseau échoue, ajoutez dans `.env` :

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

Pour activer la supervision endpoint :

```bash
make up   # puis choisir l'option 2
```

Démarre en plus :
- `wazuh-manager` — serveur Wazuh (ports 1514, 1515, 55000)
- `wazuh-indexer` — stockage OpenSearch (port 9200)

> La première fois, les certificats TLS Wazuh sont générés automatiquement (~30s).

---

## Surveiller des machines avec des agents Wazuh

> **Prérequis** : la stack Wazuh doit être démarrée (`make up` → option 2) avant d'installer un agent.

Le manager Wazuh expose ses ports sur la machine hôte (`1514` données, `1515` enrôlement).  
N'importe quelle machine du réseau peut y connecter un agent.

### Option A — Surveiller la machine qui héberge Specula

**Séquence complète pour un nouvel utilisateur :**

```bash
# 1. Démarrer la stack avec Wazuh
make up          # choisir l'option 2

# 2. Attendre que le manager soit prêt (~30s), puis installer l'agent
make agent-install   # nécessite sudo, Debian/Ubuntu uniquement

# 3. Vérifier la connexion
make agent-status
```

L'agent s'installe directement sur le système hôte (pas dans Docker) et s'enrôle automatiquement auprès du manager Specula sur `127.0.0.1`.

Ce que l'agent remonte dans la console :
- **Intégrité des fichiers** (FIM) — modifications sur `/etc`, `/bin`, `/usr`
- **Inventaire des packages** — croisé avec les CVE pour détecter les vulnérabilités
- **Logs système** — `/var/log/auth.log`, syslog, journald
- **Processus actifs** — surveillance des exécutions anormales
- **Connexions SSH et tentatives sudo**

> Si le manager n'est pas démarré, `make agent-install` affiche une erreur explicite et s'arrête.

### Option B — Surveiller une autre machine du réseau

Sur la machine distante (Debian/Ubuntu), remplacer `<IP_SPECULA>` par l'IP de la machine qui héberge Specula :

```bash
# Ajouter le dépôt Wazuh
curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg arch=amd64] \
  https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

# Installer et pointer vers le manager Specula
sudo WAZUH_MANAGER="<IP_SPECULA>" \
     WAZUH_AGENT_NAME="$(hostname)" \
     apt-get install -y wazuh-agent=4.7.2-1

sudo systemctl enable --now wazuh-agent
```

> Le port `1514` doit être accessible depuis la machine distante. Ouvrez-le dans votre firewall si nécessaire.

### Vérifier les agents connectés

```bash
make agent-status
```

---

## Commandes disponibles

```bash
# Démarrage
make check          # Vérifie Docker, ports et espace disque
make up             # Démarre Specula (choix interactif)
make open           # Ouvre la console dans le navigateur
make down           # Arrête tous les services
make rebuild        # Reconstruit les images et redémarre

# Logs (filtrés)
make logs           # Tous les services
make logs-core      # Backend + Console uniquement
make logs-suricata  # IDS réseau uniquement
make logs-wazuh     # Stack Wazuh uniquement

# Agents
make agent-install  # Installe un agent Wazuh natif sur cette machine
make agent-status   # Vérifie la connexion des agents au manager
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
| Agent natif sur hôte (`make agent-install`) | Fonctionnel |
| Détection de vulnérabilités CVE (Debian bookworm) | Fonctionnel |
| Console React — incidents, triage, notes, historique | Fonctionnel |
| Dashboard sources actives | Fonctionnel |
| Agents sur machines distantes | Manuel (voir README) |
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
