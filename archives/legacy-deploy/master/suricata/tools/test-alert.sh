#!/usr/bin/env bash
set -euo pipefail

echo "[+] Génération de trafic HTTP de test..."
curl -I http://example.com || true

echo "[+] Vérifie ensuite :"
echo "tail -f deploy/master/suricata/logs/eve.json"