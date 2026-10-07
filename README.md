# Specula — Plateforme SOC

*par [Pierre-Axel Annonier](https://p-axel.github.io/) — Ingénieur cybersécurité*

Specula surveille votre réseau et vos postes en temps réel, corrèle les alertes en incidents exploitables et vous notifie sur smartphone dès qu'une menace est détectée. Tout tourne sur votre machine — aucune donnée ne quitte votre réseau.

---

![Dashboard Specula](<Copie d'écran_20260408_145622.png>)

---

## Installation en 3 étapes

### Prérequis

- Linux (Debian / Ubuntu recommandé)
- [Docker](https://docs.docker.com/engine/install/) + Docker Compose v2
- `make`, `git`
- 4 Go RAM minimum (8 Go recommandés avec la supervision endpoint)

### Étape 1 — Récupérer Specula

```bash
git clone https://github.com/P-axel/specula.git
cd specula
```

### Étape 2 — Vérifier l'environnement

```bash
make check
```

Corrigez les éventuels `[KO]` affichés avant de continuer (Docker non démarré, port occupé, espace disque insuffisant).

### Étape 3 — Démarrer

```bash
make up
```

Choisissez votre mode au démarrage :

| Choix | Mode | Ce qui est inclus |
|---|---|---|
| `1` | Réseau | Détection réseau (Suricata IDS) |
| `2` | Complet | Réseau + supervision des postes (Wazuh) |
| `3` | Complet + IA | Réseau + postes + analyse IA locale (Ollama) |

> Le premier démarrage en mode 2 ou 3 génère les certificats TLS (~30 secondes) et télécharge les images Docker. Les démarrages suivants sont immédiats.

---

## Première connexion

```
Console : http://localhost:5173
```

**Identifiants par défaut :**

| Champ | Valeur |
|---|---|
| Identifiant | `admin` |
| Mot de passe | `specula` |

> **À faire immédiatement** : changez le mot de passe dans le fichier `.env` (`SPECULA_AUTH_PASSWORD`) et activez l'authentification (`SPECULA_AUTH_ENABLED=true`), puis relancez avec `docker restart specula-backend`.

---

## Notifications sur smartphone

Recevez une alerte push dès qu'un incident critique ou élevé est détecté.

1. Installez l'app **ntfy** sur votre téléphone (Android / iOS — gratuite, open source)
2. Dans la console Specula → menu **Notifications**
3. Scannez le QR code avec l'app ntfy
4. Cliquez **"Envoyer une notification test"** pour vérifier

Tout reste sur votre réseau — ntfy est auto-hébergé sur votre machine.

> Pour recevoir des notifications hors Wi-Fi local, renseignez l'IP LAN de votre machine dans `.env` : `NTFY_PUBLIC_URL=http://<VOTRE_IP>:2586`

---

## Connecter un poste au monitoring (agent Wazuh)

> Nécessite le mode 2 ou 3.

### Linux (Debian / Ubuntu)

Sur le poste à surveiller, remplacez `<IP_SPECULA>` par l'IP de votre serveur Specula :

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

### Windows

Depuis PowerShell en **administrateur**, remplacez `<IP_SPECULA>` :

```powershell
Invoke-Expression (
  (New-Object Net.WebClient).DownloadString(
    'https://raw.githubusercontent.com/P-axel/specula/main/scripts/install-agent-windows.ps1'
  )
) -WazuhServerIP "<IP_SPECULA>"
```

> Le port `1514` doit être accessible depuis le poste vers le serveur Specula.

---

## Démarrage automatique au boot

Pour que Specula redémarre automatiquement après un redémarrage serveur :

```bash
make up                # Lancez d'abord une fois pour enregistrer la configuration
make install-service   # Installe le service systemd (sudo requis)
```

Pour désinstaller :

```bash
make uninstall-service
```

---

## Accès aux services

| Service | Adresse |
|---|---|
| Console Specula | http://localhost:5173 |
| API / Documentation | http://localhost:8000/docs |
| Notifications (ntfy) | http://localhost:2586 |
| Wazuh Manager API | https://localhost:55000 |

---

## Commandes utiles

```bash
make check           # Vérifie l'environnement avant le démarrage
make up              # Démarre Specula
make down            # Arrête tous les services
make open            # Ouvre la console dans le navigateur
make logs            # Affiche les logs en temps réel
make rebuild         # Reconstruit les images (après mise à jour)
make reset           # Réinitialisation complète (supprime les données)
```

---

## Sécurité — checklist avant mise en production

- [ ] Changer `SPECULA_AUTH_PASSWORD` dans `.env`
- [ ] Passer `SPECULA_AUTH_ENABLED=true` dans `.env`
- [ ] Générer un secret JWT : `python3 -c "import secrets; print(secrets.token_hex(32))"`  → `SPECULA_AUTH_SECRET`
- [ ] Changer `WAZUH_INDEXER_PASSWORD` (valeur par défaut : `SecretPassword`)
- [ ] Activer HTTPS pour un accès réseau : `make up` puis choisir le profil ssl

> `make check` signale automatiquement les mots de passe par défaut non changés.

---

## Dépannage

**La console ne s'ouvre pas**
```bash
make check   # vérifie Docker et les ports
make logs    # affiche les erreurs en temps réel
```

**Interface réseau non détectée au démarrage**
```bash
ip route     # repérez le nom de l'interface (ex: eth0, enp3s0)
# Ajoutez dans .env : SURICATA_INTERFACE=eth0
```

**Wazuh ne remonte plus de données après redémarrage**
```bash
docker exec wazuh-manager /var/ossec/bin/wazuh-control start
```

**Je ne reçois pas les notifications ntfy**
- Vérifiez que votre téléphone est sur le même réseau Wi-Fi que le serveur
- Ou configurez `NTFY_PUBLIC_URL` avec l'IP LAN du serveur
- Utilisez le bouton **"Envoyer une notification test"** dans la console

---

## À propos

Pierre-Axel Annonier — Ingénieur cybersécurité

- [p-axel.github.io](https://p-axel.github.io/)
- [linkedin.com/in/pierre-axel-annonier](https://www.linkedin.com/in/pierre-axel-annonier)

---

## Licence

MIT
