#!/bin/sh
# Génère un certificat auto-signé si absent — exécuté au démarrage du conteneur nginx.
CERT_DIR=/etc/nginx/certs
CERT="$CERT_DIR/specula.crt"
KEY="$CERT_DIR/specula.key"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    echo "[specula-nginx] Certificat existant — aucune génération requise."
    exit 0
fi

mkdir -p "$CERT_DIR"
echo "[specula-nginx] Génération du certificat TLS auto-signé (10 ans)..."

openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$KEY" \
    -out "$CERT" \
    -subj "/C=FR/ST=France/O=Specula SOC/CN=specula-local" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" \
    2>/dev/null

chmod 600 "$KEY"
echo "[specula-nginx] Certificat généré : $CERT"
