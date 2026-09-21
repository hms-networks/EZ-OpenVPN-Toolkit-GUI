#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required but was not found in PATH."
  exit 1
fi

python3 -m pip show pyinstaller >/dev/null 2>&1 || python3 -m pip install pyinstaller

ICON_ARGS=()
ICON_DATA_ARGS=()
if [[ -f "HMS.ico" ]]; then
  ICON_ARGS=(--icon "HMS.ico")
  ICON_DATA_ARGS=(--add-data "HMS.ico:.")
elif [[ -f "hms.ico" ]]; then
  ICON_ARGS=(--icon "hms.ico")
  ICON_DATA_ARGS=(--add-data "hms.ico:.")
fi

DOCX_ARGS=()
while IFS= read -r -d '' docx_file; do
  file_name="$(basename "$docx_file")"
  DOCX_ARGS+=(--add-data "${file_name}:.")
done < <(find . -maxdepth 1 -type f -name "*.docx" -print0)

python3 -m PyInstaller \
  --noconfirm \
  --clean \
  --onefile \
  --name EZ-OpenVPN-Toolkit-Web \
  --add-data "needed_binaries:needed_binaries" \
  --add-data "screenshots:screenshots" \
  --add-data "exit_app.ps1:." \
  --add-data "deploy_ovpn_server_on_win10-11.ps1:." \
  --add-data "deploy_ovpn_server_linux.sh:." \
  "${ICON_DATA_ARGS[@]}" \
  "${DOCX_ARGS[@]}" \
  "${ICON_ARGS[@]}" \
  web_app.py

echo "Built dist/EZ-OpenVPN-Toolkit-Web"
