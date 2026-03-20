# 🛡️ Specula - SOC Platform

Specula est une plateforme SOC open-source permettant de :

* Collecter des événements (Wazuh, Suricata)
* Corréler des incidents
* Investiguer via une interface moderne

---
![alt text](dash.png)

## ⚡ Installation (1 commande)

     ./start-specula

### Prérequis

* Docker
* Docker Compose

### Lancer Specula

```bash
git clone https://github.com/ton-repo/specula.git
cd specula
chmod +x start-specula.sh
./start-specula.sh
```

---

## 🌐 Accès

* UI : http://localhost:5173
* API : http://localhost:8000

---

## 🧪 Mode démo (par défaut)

Specula démarre avec :

* incidents simulés
* alertes Wazuh / Suricata mockées
* corrélation active

👉 Aucun agent requis pour tester

---

## 🔌 Mode réel (optionnel)

### Wazuh (agents endpoints)

Installer un agent sur une machine :

#### Linux

```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb
sudo WAZUH_MANAGER='IP_DU_SERVEUR' dpkg -i wazuh-agent.deb
sudo systemctl start wazuh-agent
```

#### Windows

* Télécharger l’agent Wazuh
* Configurer l’IP du manager
* Démarrer le service

---

### Suricata (réseau)

```bash
sudo apt install suricata
```

Configurer `eve.json` :

```yaml
outputs:
  - eve-log:
      enabled: yes
      filename: /var/log/suricata/eve.json
```

---

## ⚙️ Configuration

Modifier `.env` :

```env
USE_FIXTURES=true
```

---

## 🧠 Architecture

* specula-core → API + corrélation
* specula-console → interface SOC
* connectors → Wazuh / Suricata
* fixtures → mode simulation

---

## 🚀 Roadmap

* Scoring intelligent
* Corrélation temps réel
* MITRE ATT&CK mapping
* Multi-tenant SOC

---

## 📄 Licence

MIT
