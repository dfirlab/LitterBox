#Requires -RunAsAdministrator
<#
.SYNOPSIS
    LitterBox Deployment Script (ADSIM-AI Fork)
    Installs, configures, and registers LitterBox using native Windows
    Task Scheduler — no third-party tools required.

.DESCRIPTION
    - Validates prerequisites (Python 3.11+, admin)
    - Installs Python dependencies
    - Creates required directories (Uploads, Results, logs)
    - Configures firewall rule for port 1337
    - Creates a Scheduled Task that runs at startup as SYSTEM
      with auto-restart on failure
    - Migrates existing MD5-prefixed uploads to SHA256 (if any)
    - Verifies health endpoint

.PARAMETER InstallPath
    Installation directory (default: C:\LitterBox)

.PARAMETER PythonPath
    Path to python.exe (auto-detected if not specified)

.PARAMETER BindIP
    IP to bind the service to (default: 0.0.0.0)

.PARAMETER Port
    Port to listen on (default: 1337)

.PARAMETER SkipMigration
    Skip the MD5-to-SHA256 hash migration step

.PARAMETER Uninstall
    Remove the LitterBox scheduled task and firewall rule

.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -InstallPath "D:\LitterBox" -BindIP "192.168.1.100"
    .\deploy.ps1 -Uninstall
#>

param(
    [string]$InstallPath = "C:\LitterBox",
    [string]$PythonPath = "",
    [string]$BindIP = "0.0.0.0",
    [int]$Port = 1337,
    [switch]$SkipMigration,
    [switch]$Uninstall
)

$TaskName = "LitterBox"
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

# ── Uninstall ──────────────────────────────────────────────────────

if ($Uninstall) {
    Write-Step "Uninstalling LitterBox"

    # Stop running process
    $procs = Get-Process python* -ErrorAction SilentlyContinue | Where-Object {
        $_.CommandLine -like "*litterbox*"
    }
    if ($procs) {
        $procs | Stop-Process -Force
        Write-OK "Stopped running LitterBox process"
    }

    # Remove scheduled task
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-OK "Scheduled task removed"
    } else {
        Write-Warn "Scheduled task not found"
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

    +===============================================+
    |     LitterBox Deployment (ADSIM-AI)           |
    |     Malware Analysis Sandbox                  |
    |     Using Windows Task Scheduler (native)     |
    +===============================================+

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
    $config = $config -replace 'host: "127.0.0.1"', "host: `"$BindIP`""
    $config = $config -replace "port: \d+", "port: $Port"
    Set-Content $configPath $config
    Write-OK "Config updated: host=$BindIP, port=$Port"
} else {
    Write-Warn "config.yaml not found — using defaults"
}

# ── Step 6: Migrate Existing Uploads ───────────────────────────────

if (-not $SkipMigration) {
    Write-Step "Checking for MD5-to-SHA256 migration"

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

# ── Step 8: Create Wrapper Script ──────────────────────────────────

Write-Step "Creating service wrapper"

# Create a wrapper batch file that Task Scheduler runs.
# This handles logging stdout/stderr and keeps the process running.
$wrapperPath = Join-Path $InstallPath "scripts\run-service.bat"
$logDir = Join-Path $InstallPath "logs"

$wrapperContent = @"
@echo off
REM LitterBox Service Wrapper — launched by Task Scheduler
REM Logs to $logDir\litterbox.log

cd /d "$InstallPath"

:loop
echo [%date% %time%] Starting LitterBox... >> "$logDir\litterbox.log"
"$PythonPath" "$InstallPath\litterbox.py" --ip $BindIP >> "$logDir\litterbox.log" 2>&1

echo [%date% %time%] LitterBox exited (code %errorlevel%). Restarting in 5 seconds... >> "$logDir\litterbox.log"
timeout /t 5 /nobreak > nul
goto loop
"@

Set-Content -Path $wrapperPath -Value $wrapperContent -Encoding ASCII
Write-OK "Wrapper: $wrapperPath (auto-restart loop)"

# ── Step 9: Register Scheduled Task ────────────────────────────────

Write-Step "Registering Scheduled Task"

# Remove existing task if present
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    # Stop if running
    if ($existingTask.State -eq "Running") {
        Stop-ScheduledTask -TaskName $TaskName
        Start-Sleep -Seconds 2
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Warn "Removed existing task"
}

# Create the task
$action = New-ScheduledTaskAction `
    -Execute "cmd.exe" `
    -Argument "/c `"$wrapperPath`"" `
    -WorkingDirectory $InstallPath

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Seconds 10) `
    -ExecutionTimeLimit (New-TimeSpan -Days 365) `
    -Priority 4

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "LitterBox Malware Analysis Sandbox (ADSIM-AI) — auto-restart on failure" | Out-Null

Write-OK "Scheduled task registered: $TaskName"
Write-OK "  Runs as: SYSTEM (highest privileges)"
Write-OK "  Trigger: At startup + auto-restart on failure"
Write-OK "  Restart: every 10 seconds, up to 999 retries"

# ── Step 10: Start the Task ────────────────────────────────────────

Write-Step "Starting LitterBox"

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5

$taskInfo = Get-ScheduledTask -TaskName $TaskName
if ($taskInfo.State -eq "Running") {
    Write-OK "Task is RUNNING"
} else {
    Write-Warn "Task state: $($taskInfo.State) — check logs"
}

# ── Step 11: Health Check ──────────────────────────────────────────

Write-Step "Running health check"

Start-Sleep -Seconds 3
try {
    $healthUrl = "http://localhost:$Port/health"
    $response = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 10
    Write-OK "Health check PASSED"
    Write-Host "    Status: $($response.status)" -ForegroundColor Green
    if ($response.version) {
        Write-Host "    Version: $($response.version)" -ForegroundColor Green
    }
} catch {
    Write-Warn "Health check failed — service may still be starting"
    Write-Host "    Try: curl http://localhost:${Port}/health" -ForegroundColor Yellow
    Write-Host "    Logs: $logDir\litterbox.log" -ForegroundColor Yellow
}

# ── Summary ────────────────────────────────────────────────────────

Write-Host @"

    +===============================================+
    |     Deployment Complete                       |
    +===============================================+

    Task:       $TaskName
    Status:     $($taskInfo.State)
    Endpoint:   http://${BindIP}:${Port}
    Health:     http://localhost:${Port}/health
    Logs:       $logDir\litterbox.log

    ADSIM-AI .env:
      LITTERBOX_URL=http://$(hostname):$Port

    Task management (PowerShell as Admin):
      Start-ScheduledTask -TaskName "$TaskName"
      Stop-ScheduledTask -TaskName "$TaskName"
      Get-ScheduledTask -TaskName "$TaskName" | Select State

    Uninstall:
      .\deploy.ps1 -Uninstall

"@ -ForegroundColor Cyan
