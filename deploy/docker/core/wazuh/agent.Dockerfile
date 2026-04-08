# Agent Wazuh dédié à Specula
# Rôle : surveiller l'infrastructure Specula elle-même (logs, fichiers système,
# packages installés, processus) et remonter les alertes au wazuh-manager.
# Construit automatiquement lors du démarrage avec --profile wazuh

FROM debian:12-slim

ARG WAZUH_VERSION=4.7.2

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        curl \
        gnupg2 \
        ca-certificates \
        procps \
        lsof \
    && curl -sS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
       | gpg --dearmor > /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg arch=amd64] \
        https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="placeholder" \
       apt-get install -y --no-install-recommends wazuh-agent="${WAZUH_VERSION}-1" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/*

ENV WAZUH_MANAGER=wazuh-manager
ENV WAZUH_AGENT_NAME=specula-host

COPY agent-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
