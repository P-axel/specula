#!/bin/bash

echo "=== Specula Deploy ==="
echo "Client : TEST"

MANAGER="192.168.1.1"

curl -so specula-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.x_amd64.deb

sudo WAZUH_MANAGER=$MANAGER dpkg -i specula-agent.deb

sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo "Specula Agent installé ✔"