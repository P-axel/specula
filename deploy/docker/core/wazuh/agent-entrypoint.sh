#!/bin/bash
# Entrypoint de l'agent Wazuh conteneurisé
# Configure l'agent et le connecte au wazuh-manager

set -euo pipefail

MANAGER="${WAZUH_MANAGER:-wazuh-manager}"
AGENT_NAME="${WAZUH_AGENT_NAME:-specula-host}"
OSSEC_CONF="/var/ossec/etc/ossec.conf"

echo "[specula/wazuh-agent] Manager : ${MANAGER}"
echo "[specula/wazuh-agent] Nom agent : ${AGENT_NAME}"

# ─── Configuration ossec.conf ────────────────────────────────────
cat > "${OSSEC_CONF}" << EOF
<ossec_config>
  <client>
    <server>
      <address>${MANAGER}</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>default</config-profile>
    <notify_time>10</notify_time>
    <time-reconnect>60</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <!-- Logs système du host (montés en volume) -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/var/log/syslog</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/var/log/auth.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/var/log/kern.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/host/var/log/dpkg.log</location>
  </localfile>

  <!-- Surveillance de l'intégrité des fichiers système -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes">/host/etc</directories>
    <ignore>/host/etc/mtab</ignore>
    <ignore>/host/etc/hosts.deny</ignore>
    <ignore>/host/etc/mail/statistics</ignore>
    <ignore>/host/etc/random-seed</ignore>
    <ignore>/host/etc/adjtime</ignore>
    <ignore>/host/etc/resolv.conf</ignore>
  </syscheck>

  <!-- Vérification de la configuration de sécurité -->
  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <!-- Surveillance des processus (nécessite pid: host) -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
  </rootcheck>

  <logging>
    <log_format>plain</log_format>
  </logging>
</ossec_config>
EOF

# ─── Enregistrement auprès du manager ────────────────────────────
echo "[specula/wazuh-agent] Attente du manager ${MANAGER}..."
for attempt in $(seq 1 30); do
    if /var/ossec/bin/agent-auth \
        -m "${MANAGER}" \
        -A "${AGENT_NAME}" \
        -v 2>/dev/null; then
        echo "[specula/wazuh-agent] Enregistrement réussi (tentative ${attempt}/30)"
        break
    fi
    if [ "${attempt}" -eq 30 ]; then
        echo "[specula/wazuh-agent] WARN: Impossible de s'enregistrer — démarrage quand même"
    else
        echo "[specula/wazuh-agent] Tentative ${attempt}/30... nouvelle tentative dans 5s"
        sleep 5
    fi
done

# ─── Démarrage de l'agent ─────────────────────────────────────────
echo "[specula/wazuh-agent] Démarrage..."
/var/ossec/bin/wazuh-agentd -f &
AGENT_PID=$!

# Redirection des logs vers stdout
tail -f /var/ossec/logs/ossec.log &

# Attendre l'arrêt du processus principal
wait "${AGENT_PID}"
