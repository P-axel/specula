# 🛡️ Specula — Plateforme SOC modulaire

Specula est une plateforme de détection et d’analyse d’événements de sécurité, pensée pour construire un SOC **plus lisible, plus exploitable et plus accessible**.

👉 Objectif : transformer des flux de sécurité complexes en **signaux utiles, corrélés et actionnables**.

🌐 https://p-axel.github.io/

---

## 📸 Aperçu

![Dashboard](dash-1.png)
![Specula](smpecula.png)

---

## 🎯 Pourquoi Specula ?

Mettre en place un SOC est souvent :

* complexe
* lourd à maintenir
* difficile à exploiter réellement

Specula propose une approche différente :

* 🔍 Se concentrer sur les bons événements
* ⚡ Corréler les signaux utiles
* 📊 Rendre l’analyse compréhensible
* 🧠 Structurer la détection plutôt que l’empiler

---

## 🧩 Architecture actuelle

Specula s’appuie aujourd’hui sur des outils spécialisés :

* **Wazuh** → collecte endpoint (logs système, sécurité)
* **Suricata** → détection réseau

⚠️ Important :

Cette version est une **première base fonctionnelle** :

* certaines briques sont encore couplées
* la modularité est **en cours de construction**

👉 Objectif : évoluer vers une plateforme **completement modulaire et extensible**

---

## 🔌 Sources de données (IMPORTANT)

Specula **ne collecte pas directement les données**.

👉 Il agit comme un **moteur de corrélation et d’analyse**, en s’appuyant sur des sources externes :

* Wazuh
* Suricata

---

### ⚠️ Agents Wazuh

Specula **ne déploie pas les agents Wazuh automatiquement**.

👉 Pour obtenir des événements système (processus, fichiers, sécurité) :

➡️ Vous devez **installer un agent Wazuh sur les machines à superviser**

Sans agent :

* vous verrez principalement les données réseau (Suricata)
* la visibilité endpoint sera limitée

---

### 🧪 Mode démo

Le déploiement fourni inclut :

* une stack Wazuh (single-node)
* Suricata
* Specula

👉 Ce mode permet de tester rapidement la plateforme,
mais nécessite des sources de données actives pour être pleinement exploitable.

---

## 🚀 Fonctionnalités

* 🔍 Ingestion d’événements (Wazuh / Suricata)
* ⚡ Corrélation d’incidents
* 📊 Interface d’analyse claire
* 🧪 Mode démo prêt à l’emploi
* 🐳 Déploiement rapide via Docker

---

## 🎯 Cas d’usage

* SOC léger pour PME
* lab cybersécurité
* analyse d’événements
* expérimentation de corrélation
* plateforme pédagogique

---

# ⚡ Installation rapide

## 🧱 Prérequis

Assurez-vous d’avoir :

* Docker installé
* Docker Compose disponible
* curl installé

---

## 🔧 1. Vérifier Docker (IMPORTANT)

```bash
docker ps
```

👉 Si vous avez une erreur :

```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

---

## 📦 2. Cloner le projet

```bash
git clone git@github.com:P-axel/specula.git
cd specula
```

---

## ⚙️ 3. Configuration

### Copier les fichiers d’environnement

```bash
cp .env.example .env
cp .env.example .env.local
```

---

### 🔥 Configurer Suricata (IMPORTANT)

Trouver votre interface réseau :

```bash
ip route
```

Exemple :

```
default via 192.168.1.1 dev wlan0
```

👉 Ajouter dans `.env` :

```bash
SURICATA_INTERFACE=wlan0
```

---

### 🎨 Configuration frontend

```bash
printf 'VITE_API_BASE_URL=http://localhost:8000\n' > specula-console/.env
```

---

## 🚀 4. Lancer Specula

```bash
chmod +x start-specula.sh
./start-specula.sh
```

---

## 🌐 Accès

* Interface : http://localhost:5173
* API : http://localhost:8000/docs
* Wazuh : https://localhost:8443

⚠️ Le dashboard Wazuh utilise un certificat auto-signé.

---

# 🧪 Vérifier que tout fonctionne

Après démarrage :

👉 Vérifiez que vous voyez :

* des événements réseau (Suricata)
* des alertes Wazuh (si agents actifs)

👉 Si rien n’apparaît :

* vérifiez Suricata
* vérifiez les agents Wazuh
* vérifiez les volumes Docker

---

# 🛠️ Dépannage rapide

## ❌ Docker non accessible

Erreur :

```
Docker is installed but not accessible
```

👉 Solution :

```bash
sudo systemctl start docker
sudo usermod -aG docker $USER
newgrp docker
```

---

## ❌ Interface Suricata invalide

Vérifier :

```bash
ip a
```

Utiliser :

* `wlan0` (Wi-Fi)
* `eth0` (Ethernet)

❌ Ne pas utiliser :

* `lo`
* `docker0`

---

## ❌ Ports déjà utilisés

```bash
lsof -i :8000
lsof -i :5173
```

---

## 🧠 Mode vérification (recommandé)

```bash
./start-specula.sh --preflight
```

👉 Vérifie :

* accès Docker
* configuration
* réseau
* variables critiques

---

# 🧠 Vision

Specula s’inscrit dans une vision claire :

* un noyau robuste et maîtrisé
* une architecture modulaire
* une corrélation intelligente des signaux
* une plateforme orientée **analyse réelle**, pas juste collecte

👉 Specula n’est pas un collecteur de logs.
👉 C’est un **moteur d’analyse et de corrélation**.

---

## 🚧 État du projet

* version actuelle : **MVP fonctionnel**
* objectif : SIEM modulaire avancé

👉 le projet évolue activement

---

## 💼 À propos

Pierre-Axel Annonier
Ingénieur cybersécurité — audit, infrastructure, automatisation

🌐 https://p-axel.github.io/
💼 https://www.linkedin.com/in/pierre-axel-annonier

---

## 📄 Licence

MIT
