Write-Host "=== Specula Deploy ==="
Write-Host "Client : {{CLIENT}}"

$manager = "{{MANAGER}}"
$group = "{{GROUP}}"
$token = "{{TOKEN}}"

$agentUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi"
$installer = "$env:TEMP\specula-agent.msi"

Invoke-WebRequest -Uri $agentUrl -OutFile $installer

Start-Process msiexec.exe -Wait -ArgumentList "/i $installer /qn WAZUH_MANAGER=$manager WAZUH_AGENT_GROUP=$group WAZUH_REGISTRATION_PASSWORD=$token"

Start-Service -Name "Wazuh"

Write-Host "Specula Agent déployé ✔"