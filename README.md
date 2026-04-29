# Specula — Plateforme SOC modulaire

*par [Pierre-Axel Annonier](https://p-axel.github.io/)*

Specula est une plateforme de détection et d'analyse d'événements de sécurité, pensée pour construire un SOC **lisible, exploitable et accessible**.

> **Statut : MVP fonctionnel — en développement actif.**

---

![alt text](<Copie d'écran_2021_145653.png>)

![alt text](<Copie d'écran_20260408_145622.png>)

---

## Pourquoi Specula ?

Mettre en place un SOC est souvent complexe, lourd et difficile à exploiter. Specula propose une approche différente :

- Se concentrer sur les bons événements, pas les empiler
- Corréler les signaux automatiquement en incidents exploitables
- Rendre l'analyse compréhensible sans noyer l'analyste
- Intégrer une IA locale pour accélérer le triage et la remédiation

**Specula n'est pas un collecteur de logs. C'est un moteur de corrélation, d'analyse et de réponse.**

---

## Architecture

```
Suricata (réseau)  ──┐
                     ├──▶ Normalizer ──▶ Correlator ──▶ FastAPI ──▶ React Console
Wazuh (endpoint)   ──┘                                      │
                                                             └──▶ Ollama IA (local)
```

- **Suricata** — IDS réseau en temps réel, actif par défaut
- **Wazuh** — supervision endpoint (logs système, processus, fichiers, vulnérabilités CVE), optionnel
- **specula-core** — backend FastAPI : ingestion, normalisation, corrélation, enrichissement IoC
- **specula-console** — interface React SOC : dashboard, triage, investigation, analyse IA
- **Ollama** — moteur IA local (qwen2.5:1.5b), analyse de menace sans cloud, optionnel

---

## Prérequis

- Docker + Docker Compose v2
- `make`
- Linux (testé Debian/Ubuntu)
- 4 Go RAM minimum, 8 Go recommandés avec Wazuh
- 10 Go disque minimum, 20 Go recommandés avec Ollama

```bash
docker ps              # vérifier que Docker tourne
docker compose version
```

---

## Installation

### 1. Cloner

```bash
git clone https://github.com/P-axel/specula.git
cd specula
```

### 2. Vérifier l'environnement

```bash
make check
```

Vérifie Docker, ports et espace disque. Corrige les `[KO]` avant de continuer.

### 3. Démarrer

```bash
make up
```

Trois modes disponibles :

```
[1] Réseau uniquement   — Suricata (IDS réseau)
[2] Stack complète      — Suricata + Wazuh (réseau + endpoints)
[3] Stack complète + IA — Suricata + Wazuh + Ollama (analyse IA locale)
```

> La première fois en mode [2] ou [3], les certificats TLS Wazuh sont générés automatiquement (~30s). Le modèle IA est téléchargé en mode [3] (~1 Go, une seule fois).

### 4. Ouvrir

```bash
make open   # http://localhost:5173
```

---

## Accès

| Service | URL |
|---|---|
| Console Specula | http://localhost:5173 |
| API (Swagger) | http://localhost:8000/docs |
| Wazuh Manager API | https://localhost:55000 |
| Ollama (si mode [3]) | http://localhost:11434 |

---

## Capacités

### Dashboard SOC

Vue opérationnelle en temps réel. Toutes les métriques affichées ont une source de données réelle :

| Métrique | Source |
|---|---|
| Incidents high/critical | Pipeline de corrélation |
| En investigation / Résolus / FP | Statuts incidents (SQLite) |
| Dwell time critique | Âge du plus vieil incident critique ouvert |
| Sources actives (Suricata / Wazuh) | Incidents par moteur |
| Actifs surveillés / actifs | Agents Wazuh connectés |
| Alertes SOC | Flux Wazuh indexer |
| Détections qualifiées | Pipeline Suricata + Wazuh |
| Activité 12h | Courbe temporelle des détections |
| Répartition par sévérité | Distribution critical/high/medium |

> Principe : aucun indicateur affiché s'il n'a pas de source de données réelle. Moins d'infos, mais fiables.

### Gestion des incidents

- **Liste avec triage** — filtres par famille, sévérité, statut, période
- **Panneau triage** — score de risque, confiance, flux réseau, threat intel, dropdown statut
- **Page d'investigation** — contexte complet, signaux liés, MITRE ATT&CK, notes, pièces jointes, historique des statuts

### Enrichissement IoC

Chaque incident réseau est enrichi automatiquement via :
- **Shodan InternetDB** — ports ouverts, CVEs exposées, tags de menace
- **abuse.ch** (optionnel) — réputation IP/domaine, malware connu

### Analyse IA locale (mode [3])

Analyse de menace sans aucun appel externe — tout tourne sur votre machine :

- **Déclenchement** : bouton "Analyser" dans le panneau triage ou la page investigation
- **Exécution** : arrière-plan (~40s), résultat automatique dès disponible
- **Modèle** : `qwen2.5:1.5b` via Ollama, CPU uniquement, ~1 Go RAM

Résultat structuré :

| Champ | Description |
|---|---|
| Type de menace | port_scan, brute_force, lateral_movement, c2_beacon... |
| Sévérité réelle | Réévaluée par l'IA vs la sévérité brute |
| Confiance | Score 0-100% |
| Risque faux positif | low / medium / high |
| Score de risque | 0-100 |
| Campagne détectée | Pattern multi-incidents |
| Action immédiate | 1ère action concrète recommandée |
| Plan de remédiation | Actions immédiates + court terme (page investigation) |

Les analyses sont persistées en SQLite — elles se rechargent instantanément à la réouverture d'un incident.

### Surveillance endpoint avec agents Wazuh

> Nécessite le mode [2] ou [3].

Ce que remonte chaque agent :
- Intégrité des fichiers (FIM) — `/etc`, `/bin`, `/usr`
- Inventaire des packages croisé avec CVEs (Debian bookworm)
- Logs système — `/var/log/auth.log`, syslog, journald
- Processus actifs et connexions réseau
- Tentatives SSH et sudo

---

## Commandes

```bash
# Démarrage
make check           # Vérifie Docker, ports, espace disque
make up              # Démarre (choix interactif : 1/2/3)
make open            # Ouvre la console dans le navigateur
make down            # Arrête tous les services
make rebuild         # Reconstruit les images

# Logs
make logs            # Tous les services
make logs-core       # Backend + Console
make logs-suricata   # IDS réseau
make logs-wazuh      # Stack Wazuh

# Agents Wazuh
make agent-install   # Installe un agent natif sur cette machine (sudo requis)
make agent-status    # Vérifie la connexion des agents

# Versions
make versions-check  # Affiche versions en cours vs disponibles
make versions-update # Met à jour vers les dernières versions stables

# Maintenance
make wazuh-reset     # Réinitialise les volumes Wazuh (en cas de problème)
make reset           # Reset complet (tous les volumes)
```

---

## Installer un agent Wazuh sur une autre machine

Sur la machine distante (Debian/Ubuntu) — remplacer `<IP_SPECULA>` :

```bash
curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
  | sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg arch=amd64] \
  https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt-get update

sudo WAZUH_MANAGER="<IP_SPECULA>" \
     WAZUH_AGENT_NAME="$(hostname)" \
     apt-get install -y wazuh-agent

sudo systemctl enable --now wazuh-agent
```

> Le port `1514` doit être accessible depuis la machine distante.

---

## Règles de détection réseau (Suricata)

| Catégorie | Exemples |
|---|---|
| Scans de ports | TCP SYN sweep, Nmap OS detection, UDP sweep |
| Brute force | SSH (5+ tentatives / 60s) |
| DNS suspect | Requêtes longues (exfiltration), volume élevé (tunneling / DGA) |
| C2 / backdoors | Ports 4444, 1337, 31337, 6667 (IRC) |
| Attaques web | SQL injection, path traversal, upload PHP |
| Protocoles non chiffrés | FTP, Telnet |
| Flood | ICMP flood (50+ pings / 5s) |

---

## Dépannage

**Interface réseau non détectée**
```bash
ip route   # identifier l'interface
# puis dans .env : SURICATA_INTERFACE=eth0
```

**Backend lent au premier chargement**  
Normal — le cache se précauffe au démarrage (~30s). Les requêtes suivantes répondent en <200ms.

**Wazuh ne remonte rien après redémarrage**
```bash
docker exec wazuh-manager /var/ossec/bin/wazuh-control start
```

**Analyse IA bloquée**  
L'analyse peut être relancée depuis le panneau triage. Les analyses bloquées sont automatiquement remises en erreur au prochain démarrage du backend.

**Voir les logs**
```bash
make logs
```

---

## État du projet

| Brique | État |
|---|---|
| Suricata IDS + corrélation d'incidents | ✅ Fonctionnel |
| Ingestion Wazuh (manager + indexer + agent) | ✅ Fonctionnel |
| Détection de vulnérabilités CVE (Debian bookworm) | ✅ Fonctionnel |
| Enrichissement IoC (Shodan + abuse.ch) | ✅ Fonctionnel |
| Console React — dashboard, triage, investigation | ✅ Fonctionnel |
| Notes, pièces jointes, historique statuts | ✅ Fonctionnel |
| Analyse IA locale (Ollama, sans cloud) | ✅ Fonctionnel |
| Cache TTL backend — dashboard <200ms | ✅ Fonctionnel |
| Limites ressources Docker (host protégé) | ✅ Fonctionnel |
| Tests automatisés | ⚠️ Partiel |
| Connecteurs supplémentaires (Elastic, Splunk…) | 🔜 Prévu |

---

## À propos

Pierre-Axel Annonier — Ingénieur cybersécurité

- https://p-axel.github.io/
- https://www.linkedin.com/in/pierre-axel-annonier

---

## Licence

MIT
