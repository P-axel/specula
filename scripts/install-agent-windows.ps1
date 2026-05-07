# ============================================================
#  Specula — Installation agent Windows
#  Lance ce script en tant qu'Administrateur sur le PC Windows
#  > Set-ExecutionPolicy Bypass -Scope Process -Force
#  > .\install-agent-windows.ps1
# ============================================================

$SPECULA_MANAGER = "192.168.1.1"
$WAZUH_VERSION   = "4.14.4"
$AGENT_NAME      = $env:COMPUTERNAME   # nom du PC Windows automatiquement

Write-Host ""
Write-Host "  Specula — Installation agent Windows" -ForegroundColor Cyan
Write-Host "  =====================================" -ForegroundColor Cyan
Write-Host "  Manager : $SPECULA_MANAGER"
Write-Host "  Agent   : $AGENT_NAME"
Write-Host "  Version : $WAZUH_VERSION"
Write-Host ""

# ── Vérification droits admin ─────────────────────────────────
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[ERREUR] Ce script doit etre lance en tant qu'Administrateur." -ForegroundColor Red
    Write-Host "         Clic droit sur PowerShell > Executer en tant qu'administrateur" -ForegroundColor Yellow
    exit 1
}

# ── Téléchargement du MSI ─────────────────────────────────────
$msiUrl  = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WAZUH_VERSION-1.msi"
$msiPath = "$env:TEMP\wazuh-agent-$WAZUH_VERSION.msi"

if (Test-Path $msiPath) {
    Write-Host "[INFO] Installeur deja present : $msiPath"
} else {
    Write-Host "[INFO] Telechargement de l'agent Wazuh $WAZUH_VERSION..."
    try {
        Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
        Write-Host "[OK] Telechargement termine." -ForegroundColor Green
    } catch {
        Write-Host "[ERREUR] Echec du telechargement : $_" -ForegroundColor Red
        exit 1
    }
}

# ── Installation silencieuse ──────────────────────────────────
Write-Host "[INFO] Installation en cours..."
$installArgs = @(
    "/i", $msiPath,
    "/q",
    "WAZUH_MANAGER=$SPECULA_MANAGER",
    "WAZUH_MANAGER_PORT=1514",
    "WAZUH_AGENT_NAME=$AGENT_NAME"
)

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru
if ($process.ExitCode -ne 0) {
    Write-Host "[ERREUR] Installation echouee (code $($process.ExitCode))" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Agent installe." -ForegroundColor Green

# ── Démarrage du service ──────────────────────────────────────
Write-Host "[INFO] Demarrage du service Wazuh..."
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Set-Service  -Name "WazuhSvc" -StartupType Automatic

$svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[OK] Service Wazuh actif." -ForegroundColor Green
} else {
    Write-Host "[WARN] Service non demarré — verifiez dans services.msc" -ForegroundColor Yellow
}

# ── Résumé ────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host "  Agent installe sur : $AGENT_NAME"               -ForegroundColor Cyan
Write-Host "  Connecte a         : $SPECULA_MANAGER:1514"      -ForegroundColor Cyan
Write-Host "  Visible dans       : http://192.168.1.1:5173/assets" -ForegroundColor Cyan
Write-Host "  ================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  L'agent apparait dans Specula sous 1-2 minutes." -ForegroundColor Green
Write-Host ""
