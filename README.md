# 🛡️ Specula — Plateforme SOC modulaire

Specula est une plateforme de détection et d’analyse d’événements de sécurité, pensée pour construire un SOC **plus lisible, plus exploitable et plus accessible**.

👉 Objectif : transformer des flux de sécurité complexes en signaux utiles, corrélés et actionnables.

🌐  https://p-axel.github.io/

---

## 📸 Aperçu

![alt text](dash-1.png)
![alt text](smpecula.png)
---

## 🎯 Pourquoi Specula ?

Mettre en place un SOC est souvent complexe, lourd et difficile à exploiter.

Specula propose une approche différente :

- 🔍 Collecter les bons événements
- ⚡ Corréler les signaux utiles
- 📊 Rendre l’analyse compréhensible
- 🧠 Structurer la détection plutôt que l’empiler

---

## 🧩 Architecture actuelle

Specula s’appuie aujourd’hui sur :

- **Wazuh** → collecte endpoint
- **Suricata** → détection réseau

⚠️ Important :

Cette version est une **première base fonctionnelle**.

- les briques sont encore liées
- la modularité est **pensée mais en cours de construction**

👉 Objectif : évoluer vers une plateforme réellement modulaire et extensible

---

## 🚀 Fonctionnalités

- 🔍 Collecte d’événements (Wazuh / Suricata)
- ⚡ Corrélation d’incidents
- 📊 Interface d’analyse claire
- 🧪 Mode démo prêt à l’emploi
- 🐳 Déploiement rapide via Docker

---

## 🎯 Cas d’usage

- SOC léger pour PME
- lab cybersécurité
- analyse d’événements
- expérimentation de corrélation

---

## ⚡ Installation

```bash
git clone git@github.com:P-axel/specula.git
cd specula
cp .env.example .env
cp .env.example .env.local
printf 'VITE_API_BASE_URL=http://localhost:8000\n' > specula-console/.env

# Adapter l'interface réseau pour Suricata
# SURICATA_INTERFACE=...

chmod +x start-specula.sh
./start-specula.sh
```

---

## 🧠 Vision

Specula s’inscrit dans une vision plus large :

- un noyau robuste et maîtrisé
- une architecture modulaire
- une corrélation intelligente des signaux
- une plateforme orientée **analyse réelle**, pas juste collecte

---

## 🚧 État du projet

- version actuelle : **MVP fonctionnel**
- objectif : SIEM modulaire avancé

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
