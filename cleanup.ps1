# Folder to clean (current folder)
$folder = Get-Location

# Files/folders to KEEP
$keep = @(
    "web_app.py",
    "ca_setup.py",
    "client_manager.py",
    "config.py",
    "helpers.py",
    "logger.py",
    "openvpn_config.py",
    "subnet_management.py",
    "build_web_gui_exe.ps1",
    "README.md",
    "client_cert.py",
    "client_revoke.py",
    "deploy_ovpn_server_linux.sh",
    "deploy_ovpn_server_on_win10-11.ps1",
    "deploy_server.py",
    "EZOpenVPNToolkit.docx",
	"Deploy Client Package to Cosy+_Flexy.docx",
	"Deploy Server Setup to Anybus Defender.docx",
	"Deploy Server Package to FlexEdge.docx",
	"Deploy Server Package to Linux.docx",
	"Deploy Server Package to Windows.docx",
    "HMS.ico",
    "openvpn_package_generator_windows.py",
    "server_cert.py",
    "main.py",
    "testing",
    "needed_binaries",
	"cleanup.ps1",
    "exit_app.ps1"
)

Get-ChildItem -Path $folder | ForEach-Object {
    if ($keep -notcontains $_.Name) {
        Write-Host "Deleting:" $_.Name
        Remove-Item $_.FullName -Recurse -Force
    }
}