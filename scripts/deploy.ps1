#Requires -RunAsAdministrator
<#
.SYNOPSIS
    LitterBox Deployment Script (ADSIM-AI Fork)
    Installs, configures, and registers LitterBox as a Windows service.

.DESCRIPTION
    - Validates prerequisites (Python 3.11+, admin, NSSM)
    - Installs Python dependencies
    - Creates required directories (Uploads, Results, logs)
    - Configures firewall rule for port 1337
    - Registers and starts LitterBox as a Windows service via NSSM
    - Migrates existing MD5-prefixed uploads to SHA256 (if any)
    - Verifies health endpoint

.PARAMETER InstallPath
    Installation directory (default: C:\LitterBox)

.PARAMETER NssmPath
    Path to nssm.exe (default: C:\nssm\nssm.exe)

.PARAMETER PythonPath
    Path to python.exe (auto-detected if not specified)

.PARAMETER BindIP
    IP to bind the service to (default: 0.0.0.0)

.PARAMETER Port
    Port to listen on (default: 1337)

.PARAMETER SkipMigration
    Skip the MD5→SHA256 hash migration step

.PARAMETER Uninstall
    Remove the LitterBox service and firewall rule

.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -InstallPath "D:\LitterBox" -BindIP "192.168.1.100"
    .\deploy.ps1 -Uninstall
#>

param(
    [string]$InstallPath = "C:\LitterBox",
    [string]$NssmPath = "C:\nssm\nssm.exe",
    [string]$PythonPath = "",
    [string]$BindIP = "0.0.0.0",
    [int]$Port = 1337,
    [switch]$SkipMigration,
    [switch]$Uninstall
)

$ServiceName = "LitterBox"
$ErrorActionPreference = "Stop"

# ── Helpers ────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Message)
    Write-Host "`n[*] $Message" -ForegroundColor Cyan
}

function Write-OK {
    param([string]$Message)
    Write-Host "    [+] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "    [!] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "    [-] $Message" -ForegroundColor Red
}

function Test-ServiceExists {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    return $null -ne $svc
}

# ── Uninstall ──────────────────────────────────────────────────────

if ($Uninstall) {
    Write-Step "Uninstalling LitterBox service"

    if (Test-ServiceExists $ServiceName) {
        & $NssmPath stop $ServiceName 2>$null
        & $NssmPath remove $ServiceName confirm
        Write-OK "Service removed"
    } else {
        Write-Warn "Service not found"
    }

    # Remove firewall rule
    $rule = Get-NetFirewallRule -DisplayName "LitterBox" -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -DisplayName "LitterBox"
        Write-OK "Firewall rule removed"
    }

    Write-Host "`nLitterBox uninstalled. Files at $InstallPath are NOT deleted." -ForegroundColor Cyan
    exit 0
}

# ── Banner ─────────────────────────────────────────────────────────

Write-Host @"

    ╔═══════════════════════════════════════════╗
    ║     LitterBox Deployment (ADSIM-AI)       ║
    ║     Malware Analysis Sandbox              ║
    ╚═══════════════════════════════════════════╝

"@ -ForegroundColor Magenta

# ── Step 1: Validate Prerequisites ─────────────────────────────────

Write-Step "Checking prerequisites"

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "Must run as Administrator"
    exit 1
}
Write-OK "Running as Administrator"

# Python
if (-not $PythonPath) {
    $PythonPath = (Get-Command python -ErrorAction SilentlyContinue).Source
    if (-not $PythonPath) {
        $PythonPath = (Get-Command python3 -ErrorAction SilentlyContinue).Source
    }
}
if (-not $PythonPath -or -not (Test-Path $PythonPath)) {
    Write-Fail "Python not found. Install Python 3.11+ and add to PATH, or use -PythonPath"
    exit 1
}
$pyVersion = & $PythonPath --version 2>&1
Write-OK "Python: $pyVersion ($PythonPath)"

# NSSM
if (-not (Test-Path $NssmPath)) {
    Write-Warn "NSSM not found at $NssmPath"
    Write-Host "    Downloading NSSM..." -ForegroundColor Yellow

    $nssmDir = Split-Path $NssmPath
    if (-not (Test-Path $nssmDir)) { New-Item -ItemType Directory -Path $nssmDir -Force | Out-Null }

    $nssmZip = "$env:TEMP\nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $nssmZip
    Expand-Archive -Path $nssmZip -DestinationPath "$env:TEMP\nssm_extract" -Force
    Copy-Item "$env:TEMP\nssm_extract\nssm-2.24\win64\nssm.exe" $NssmPath
    Remove-Item $nssmZip -Force
    Remove-Item "$env:TEMP\nssm_extract" -Recurse -Force

    if (Test-Path $NssmPath) {
        Write-OK "NSSM downloaded to $NssmPath"
    } else {
        Write-Fail "NSSM download failed. Download manually from https://nssm.cc/"
        exit 1
    }
}
Write-OK "NSSM: $NssmPath"

# ── Step 2: Validate Installation ──────────────────────────────────

Write-Step "Validating LitterBox installation at $InstallPath"

if (-not (Test-Path "$InstallPath\litterbox.py")) {
    Write-Fail "litterbox.py not found at $InstallPath"
    Write-Host "    Clone the repo first: git clone https://github.com/dfirlab/LitterBox.git $InstallPath"
    exit 1
}
Write-OK "litterbox.py found"

# Check scanners
$scannerPath = Join-Path $InstallPath "Scanners"
if (Test-Path $scannerPath) {
    $scanners = Get-ChildItem $scannerPath -Directory
    Write-OK "Scanners: $($scanners.Count) tools ($($scanners.Name -join ', '))"
} else {
    Write-Warn "Scanners directory not found — dynamic analysis will be limited"
}

# ── Step 3: Install Dependencies ───────────────────────────────────

Write-Step "Installing Python dependencies"
Push-Location $InstallPath
& $PythonPath -m pip install -r requirements.txt --quiet 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-OK "Dependencies installed"
} else {
    Write-Warn "Some dependencies may have failed — check manually"
}
Pop-Location

# ── Step 4: Create Directories ─────────────────────────────────────

Write-Step "Creating required directories"

$dirs = @(
    (Join-Path $InstallPath "Uploads"),
    (Join-Path $InstallPath "Results"),
    (Join-Path $InstallPath "logs")
)
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-OK "Created $dir"
    } else {
        Write-OK "Exists: $dir"
    }
}

# ── Step 5: Update Config ──────────────────────────────────────────

Write-Step "Updating configuration"

$configPath = Join-Path $InstallPath "Config\config.yaml"
if (Test-Path $configPath) {
    $config = Get-Content $configPath -Raw
    # Update host to bind IP
    $config = $config -replace 'host: "127.0.0.1"', "host: `"$BindIP`""
    $config = $config -replace "port: \d+", "port: $Port"
    Set-Content $configPath $config
    Write-OK "Config updated: host=$BindIP, port=$Port"
} else {
    Write-Warn "config.yaml not found — using defaults"
}

# ── Step 6: Migrate Existing Uploads ───────────────────────────────

if (-not $SkipMigration) {
    Write-Step "Checking for MD5→SHA256 migration"

    $migrationScript = Join-Path $InstallPath "scripts\migrate_hashes.py"
    $uploadsDir = Join-Path $InstallPath "Uploads"
    $resultsDir = Join-Path $InstallPath "Results"

    if ((Test-Path $migrationScript) -and (Test-Path $resultsDir)) {
        $existingResults = Get-ChildItem $resultsDir -Directory -ErrorAction SilentlyContinue
        if ($existingResults.Count -gt 0) {
            Write-Host "    Found $($existingResults.Count) existing results — running migration..." -ForegroundColor Yellow
            Push-Location $InstallPath
            & $PythonPath $migrationScript --upload-dir $uploadsDir --result-dir $resultsDir
            Pop-Location
        } else {
            Write-OK "No existing uploads to migrate"
        }
    } else {
        Write-OK "No migration needed (clean install)"
    }
}

# ── Step 7: Configure Firewall ─────────────────────────────────────

Write-Step "Configuring Windows Firewall"

$existingRule = Get-NetFirewallRule -DisplayName "LitterBox" -ErrorAction SilentlyContinue
if ($existingRule) {
    Remove-NetFirewallRule -DisplayName "LitterBox"
}
New-NetFirewallRule -DisplayName "LitterBox" `
    -Direction Inbound `
    -Action Allow `
    -Protocol TCP `
    -LocalPort $Port `
    -Description "LitterBox Malware Analysis Sandbox (ADSIM-AI)" | Out-Null
Write-OK "Firewall rule: allow TCP $Port inbound"

# ── Step 8: Register Windows Service ───────────────────────────────

Write-Step "Registering Windows service"

# Stop and remove existing service if present
if (Test-ServiceExists $ServiceName) {
    Write-Warn "Existing service found — stopping and removing"
    & $NssmPath stop $ServiceName 2>$null
    Start-Sleep -Seconds 2
    & $NssmPath remove $ServiceName confirm 2>$null
    Start-Sleep -Seconds 1
}

# Install service
& $NssmPath install $ServiceName $PythonPath "$InstallPath\litterbox.py --ip $BindIP"
& $NssmPath set $ServiceName AppDirectory $InstallPath
& $NssmPath set $ServiceName DisplayName "LitterBox Malware Sandbox"
& $NssmPath set $ServiceName Description "LitterBox malware analysis sandbox for ADSIM-AI red team operations"
& $NssmPath set $ServiceName Start SERVICE_AUTO_START
& $NssmPath set $ServiceName AppRestartDelay 5000
& $NssmPath set $ServiceName AppStopMethodSkip 6
& $NssmPath set $ServiceName AppStopMethodConsole 3000
& $NssmPath set $ServiceName AppStopMethodWindow 3000

# Configure logging
$logDir = Join-Path $InstallPath "logs"
& $NssmPath set $ServiceName AppStdout "$logDir\litterbox-stdout.log"
& $NssmPath set $ServiceName AppStderr "$logDir\litterbox-stderr.log"
& $NssmPath set $ServiceName AppRotateFiles 1
& $NssmPath set $ServiceName AppRotateBytes 10485760  # 10MB

Write-OK "Service registered: $ServiceName"

# ── Step 9: Start Service ──────────────────────────────────────────

Write-Step "Starting LitterBox service"

& $NssmPath start $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-OK "Service is RUNNING (PID: $($svc.ServiceHandle))"
} else {
    Write-Warn "Service may not have started — check logs at $logDir"
}

# ── Step 10: Health Check ──────────────────────────────────────────

Write-Step "Running health check"

Start-Sleep -Seconds 2
try {
    $healthUrl = "http://localhost:$Port/health"
    $response = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
    Write-OK "Health check PASSED"
    Write-Host "    Status: $($response.status)" -ForegroundColor Green
    Write-Host "    Version: $($response.version)" -ForegroundColor Green
} catch {
    Write-Warn "Health check failed — service may still be starting"
    Write-Host "    Try: curl http://localhost:$Port/health" -ForegroundColor Yellow
    Write-Host "    Logs: $logDir\litterbox-stderr.log" -ForegroundColor Yellow
}

# ── Summary ────────────────────────────────────────────────────────

Write-Host @"

    ╔═══════════════════════════════════════════╗
    ║     Deployment Complete                   ║
    ╚═══════════════════════════════════════════╝

    Service:    $ServiceName
    Status:     $(if ($svc -and $svc.Status -eq 'Running') { 'RUNNING' } else { 'CHECK LOGS' })
    Endpoint:   http://${BindIP}:${Port}
    Health:     http://localhost:${Port}/health
    Logs:       $logDir\

    ADSIM-AI .env:
    LITTERBOX_URL=http://$(hostname):$Port

    Service management:
    $NssmPath start $ServiceName
    $NssmPath stop $ServiceName
    $NssmPath restart $ServiceName
    $NssmPath status $ServiceName

"@ -ForegroundColor Cyan
