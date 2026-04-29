#!/usr/bin/env bash

echo "=== Suricata container ==="
docker ps | grep suricata

echo
echo "=== Logs eve.json ==="
if [ -f logs/eve.json ]; then
    ls -lh logs/eve.json
else
    echo "eve.json pas encore généré"
fi