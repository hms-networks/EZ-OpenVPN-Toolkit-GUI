$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is required but was not found in PATH."
}

python -m pip show pyinstaller *> $null
if ($LASTEXITCODE -ne 0) {
    python -m pip install pyinstaller
}

$iconArg = @()
$iconDataArg = @()
$docxDataArgs = @()
$iconName = $null

if (Test-Path ".\HMS.ico") {
    $iconName = "HMS.ico"
} elseif (Test-Path ".\hms.ico") {
    $iconName = "hms.ico"
}

if ($iconName) {
    $iconArg = @("--icon", $iconName)
    $iconDataArg = @("--add-data", "$iconName;.")
} else {
    Write-Warning "No icon file found (expected HMS.ico or hms.ico)."
}

Get-ChildItem -Path . -Filter *.docx -File | ForEach-Object {
    $docxDataArgs += @("--add-data", "$($_.Name);.")
}

python -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --name EZ-OpenVPN-Toolkit-Web `
    --add-data "needed_binaries;needed_binaries" `
    --add-data "exit_app.ps1;." `
    --add-data "deploy_ovpn_server_on_win10-11.ps1;." `
    --add-data "deploy_ovpn_server_linux.sh;." `
    @docxDataArgs `
    @iconDataArg `
    @iconArg `
    web_app.py

Write-Host "Built dist\EZ-OpenVPN-Toolkit-Web.exe"
Pop-Location
