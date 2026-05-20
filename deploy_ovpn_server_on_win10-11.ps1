# =========================================================
# deploy_ovpn_server_on_win10-11.ps1
# =========================================================

# --- Ensure running as Administrator ---
$currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentIdentity)
$isAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin)
{
    Write-Host "Relaunching as Administrator..." -ForegroundColor Yellow

    Start-Process powershell `
        "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" `
        -Verb RunAs

    exit
}

Write-Host "`n=== OpenVPN Server Deployment ===`n" -ForegroundColor Cyan

# ---------------------------------------------------------
# Detect OpenVPN Installation
# ---------------------------------------------------------

$possiblePaths = @(
    "C:\Program Files\OpenVPN\bin",
    "C:\Program Files (x86)\OpenVPN\bin"
)

$openvpnBase = $null

foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $openvpnBase = $path
        break
    }
}

if (-not $openvpnBase) {
    Write-Host "ERROR: OpenVPN installation not found." -ForegroundColor Red
    exit 1
}

Write-Host "OpenVPN installation found at:"
Write-Host "  $openvpnBase" -ForegroundColor Green

$openvpnGui = Join-Path $openvpnBase "openvpn-gui.exe"
$openvpnExe = Join-Path $openvpnBase "openvpn.exe"

if (Test-Path $openvpnGui) {
    Write-Host "OpenVPN GUI detected."
}
elseif (Test-Path $openvpnExe) {
    Write-Host "OpenVPN CLI detected."
}
else {
    Write-Host "ERROR: OpenVPN binaries not found." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

$scriptRoot = Split-Path -Parent $PSCommandPath

$newServerDir  = Join-Path $scriptRoot "server"
$newServerConf = Join-Path $newServerDir "server.conf"
$newCcdDir     = Join-Path $newServerDir "ccd"

$configDir = Join-Path (Split-Path $openvpnBase -Parent) "config"

$targetConfig = Join-Path $configDir "server.ovpn"
$targetCcdDir = Join-Path $configDir "ccd"

# ---------------------------------------------------------
# Validate Input
# ---------------------------------------------------------

if (!(Test-Path $newServerConf)) {
    Write-Host "ERROR: server.conf not found in extracted package." -ForegroundColor Red
    exit 1
}

# ---------------------------------------------------------
# Pre-Clean Existing Files
# ---------------------------------------------------------

Write-Host "`nChecking for existing OpenVPN server artifacts..." -ForegroundColor Cyan

$itemsToRemove = @(
    "server",
    "ccd",
    "server.ovpn",
    "server.conf",
    "ipp.txt",
    "openvpn-status.log",
    "openvpn.log"
)

$foundItems = @()

foreach ($item in $itemsToRemove) {
    $fullPath = Join-Path $configDir $item

    if (Test-Path $fullPath) {
        $foundItems += $fullPath
    }
}

if ($foundItems.Count -gt 0) {

    Write-Host "`nWARNING: Existing OpenVPN-related files/folders detected:" -ForegroundColor Yellow

    $foundItems | ForEach-Object {
        Write-Host " - $_"
    }

    $confirmation = Read-Host "`nRemove these items before deployment? (Y/N)"

    if ($confirmation -notin @("Y", "y")) {
        Write-Host "Deployment aborted." -ForegroundColor Red
        exit 1
    }

    foreach ($item in $foundItems) {

        try {
            Remove-Item $item -Recurse -Force -ErrorAction Stop
            Write-Host "Removed: $item"
        }
        catch {
            Write-Host "Failed to remove: $item" -ForegroundColor Red
        }
    }
}
else {
    Write-Host "No conflicting files found."
}

# ---------------------------------------------------------
# Deploy Config
# ---------------------------------------------------------

Write-Host "`nDeploying OpenVPN server configuration..."

New-Item -ItemType Directory -Path $configDir -Force | Out-Null

Copy-Item $newServerConf $targetConfig -Force

Write-Host "Copied server.ovpn"

# ---------------------------------------------------------
# Deploy CCD
# ---------------------------------------------------------

if (Test-Path $newCcdDir) {

    Write-Host "Deploying CCD directory..."

    Copy-Item $newCcdDir `
        -Destination $targetCcdDir `
        -Recurse `
        -Force

    Write-Host "CCD directory deployed."
}

# ---------------------------------------------------------
# Firewall Rules
# ---------------------------------------------------------

Write-Host "`nConfiguring firewall rules..."

# UDP 1194
New-NetFirewallRule `
    -DisplayName "OpenVPN UDP 1194" `
    -Direction Inbound `
    -Protocol UDP `
    -LocalPort 1194 `
    -Action Allow `
    -Profile Any `
    -ErrorAction SilentlyContinue | Out-Null

# TCP 7505
New-NetFirewallRule `
    -DisplayName "OpenVPN Management 7505" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 7505 `
    -Action Allow `
    -Profile Any `
    -ErrorAction SilentlyContinue | Out-Null

Write-Host "Firewall rules configured."

# ---------------------------------------------------------
# Ensure ipp.txt Exists
# ---------------------------------------------------------

$ippPath = Join-Path $configDir "ipp.txt"

if (!(Test-Path $ippPath)) {
    New-Item $ippPath -ItemType File | Out-Null
}

# ---------------------------------------------------------
# Stop Existing OpenVPN Processes
# ---------------------------------------------------------

Write-Host "`nStopping existing OpenVPN processes..."

Get-Process openvpn -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process openvpn-gui -ErrorAction SilentlyContinue | Stop-Process -Force

Start-Sleep -Seconds 2

# ---------------------------------------------------------
# Create Scheduled Task
# ---------------------------------------------------------

Write-Host "`nCreating OpenVPN auto-start scheduled task..."

$taskName = "OpenVPN Server AutoStart"

Unregister-ScheduledTask `
    -TaskName $taskName `
    -Confirm:$false `
    -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction `
    -Execute $openvpnExe `
    -Argument "--config `"$targetConfig`"" `
    -WorkingDirectory $configDir

$trigger = New-ScheduledTaskTrigger -AtStartup

$principal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal | Out-Null

Write-Host "Scheduled task created."

# ---------------------------------------------------------
# Start OpenVPN Immediately
# ---------------------------------------------------------

Write-Host "`nStarting OpenVPN server..."

Start-ScheduledTask -TaskName $taskName

Start-Sleep -Seconds 5

# ---------------------------------------------------------
# Scheduled Task Status Check
# ---------------------------------------------------------

Write-Host "`nChecking scheduled task status..." -ForegroundColor Cyan

$task = Get-ScheduledTask `
    -TaskName $taskName `
    -ErrorAction SilentlyContinue

if ($task) {

    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName

    Write-Host "Task Name    : $($task.TaskName)"
    Write-Host "State        : $($task.State)"
    Write-Host "Last Run     : $($taskInfo.LastRunTime)"
    Write-Host "Last Result  : $($taskInfo.LastTaskResult)"

    if ($taskInfo.LastTaskResult -eq 0) {
        Write-Host "Task Status  : SUCCESS" -ForegroundColor Green
    }
    else {
        Write-Host "Task Status  : WARNING / CHECK RESULT CODE" -ForegroundColor Yellow
    }
}
else {
    Write-Host "Scheduled task NOT found." -ForegroundColor Red
}

# ---------------------------------------------------------
# OpenVPN Startup Validation
# ---------------------------------------------------------

Write-Host "`nWaiting for OpenVPN to initialize..." -ForegroundColor Cyan

$maxAttempts = 20
$attempt = 0

$vpnReady = $false
$mgmtReady = $false
$tapReady = $false

while ($attempt -lt $maxAttempts)
{
    $attempt++

    Write-Host "`nValidation Attempt $attempt/$maxAttempts..." -ForegroundColor Yellow

    # ---------------------------------------------------------
    # Check UDP 1194
    # ---------------------------------------------------------

    $vpnPort = netstat -ano | findstr "UDP" | findstr ":1194"

    if ($vpnPort)
    {
        Write-Host "UDP 1194 is listening." -ForegroundColor Green
        $vpnReady = $true
    }
    else
    {
        Write-Host "UDP 1194 not ready yet."
    }

    # ---------------------------------------------------------
    # Check TCP 7505 (Management Interface)
    # ---------------------------------------------------------

    $mgmtPort = netstat -ano | findstr "LISTENING" | findstr ":7505"

    if ($mgmtPort)
    {
        Write-Host "TCP 7505 management interface is listening." -ForegroundColor Green
        $mgmtReady = $true
    }
    else
    {
        Write-Host "TCP 7505 not ready yet."
    }

    # ---------------------------------------------------------
    # Check TAP Adapter IP
    # ---------------------------------------------------------

    $tapCheck = ipconfig | findstr "10.0.0.1"

    if ($tapCheck)
    {
        Write-Host "TAP adapter initialized with 10.0.0.1." -ForegroundColor Green
        $tapReady = $true
    }
    else
    {
        Write-Host "TAP adapter not ready yet."
    }

    # ---------------------------------------------------------
    # Success Condition
    # ---------------------------------------------------------

    if ($vpnReady -and $mgmtReady -and $tapReady)
    {
        Write-Host "`nOpenVPN initialized successfully." -ForegroundColor Green
        break
    }

    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------
# Final Validation Result
# ---------------------------------------------------------

if (-not ($vpnReady -and $mgmtReady -and $tapReady))
{
    Write-Host "`nERROR: OpenVPN validation failed." -ForegroundColor Red

    Write-Host "`nValidation Status:" -ForegroundColor Yellow
    Write-Host "UDP 1194 Ready : $vpnReady"
    Write-Host "TCP 7505 Ready : $mgmtReady"
    Write-Host "TAP Adapter    : $tapReady"

    Write-Host "`nRecent OpenVPN Processes:" -ForegroundColor Cyan
    Get-Process openvpn -ErrorAction SilentlyContinue

    Write-Host "`nCurrent Listening Ports:" -ForegroundColor Cyan
    netstat -ano | findstr "1194"
    netstat -ano | findstr "7505"

    exit 1
}

Write-Host "`nOpenVPN deployment validation PASSED." -ForegroundColor Green

Write-Host "`nDeployment complete.`n" -ForegroundColor Green