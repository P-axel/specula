# 🛡️ Specula — Plateforme SOC modulaire

Specula est une plateforme de détection et d’analyse d’événements de sécurité, pensée pour construire un SOC **plus lisible, plus exploitable et plus accessible**.

👉 Objectif : transformer des flux de sécurité complexes en signaux utiles, corrélés et actionnables.

🌐 https://p-axel.github.io/

---

## 📸 Aperçu

![Dashboard](dash-1.png)
![Specula](smpecula.png)

---

## 🎯 Pourquoi Specula ?

Mettre en place un SOC est souvent complexe, lourd et difficile à exploiter.

Specula propose une approche différente :

* 🔍 Collecter les bons événements
* ⚡ Corréler les signaux utiles
* 📊 Rendre l’analyse compréhensible
* 🧠 Structurer la détection plutôt que l’empiler

---

## 🧩 Architecture actuelle

Specula s’appuie aujourd’hui sur :

* **Wazuh** → collecte endpoint
* **Suricata** → détection réseau

⚠️ Important :

Cette version est une **première base fonctionnelle**.

* les briques sont encore liées
* la modularité est **pensée mais en cours de construction**

👉 Objectif : évoluer vers une plateforme réellement modulaire et extensible

---

## 🚀 Fonctionnalités

* 🔍 Collecte d’événements (Wazuh / Suricata)
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

Specula s’inscrit dans une vision plus large :

* un noyau robuste et maîtrisé
* une architecture modulaire
* une corrélation intelligente des signaux
* une plateforme orientée **analyse réelle**, pas juste collecte

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
