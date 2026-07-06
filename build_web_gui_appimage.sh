#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BIN_NAME="EZ-OpenVPN-Toolkit-Web"
APP_NAME="EZ-OpenVPN-Toolkit-Web"
APPDIR="$SCRIPT_DIR/AppDir"
DIST_BIN="$SCRIPT_DIR/dist/$BIN_NAME"

if [[ ! -x "$DIST_BIN" ]]; then
  echo "Linux binary not found. Building it first..."
  "$SCRIPT_DIR/build_web_gui_linux.sh"
fi

if ! command -v appimagetool >/dev/null 2>&1; then
  cat <<'EOF'
appimagetool is required to create an AppImage.
Install one of these ways, then re-run this script:
  1) Debian/Ubuntu: sudo apt-get install appimagetool
  2) Fedora: sudo dnf install appimagetool
  3) Download from: https://github.com/AppImage/AppImageKit/releases
EOF
  exit 1
fi

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications"

cp "$DIST_BIN" "$APPDIR/usr/bin/$BIN_NAME"
chmod +x "$APPDIR/usr/bin/$BIN_NAME"

cat > "$APPDIR/AppRun" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$HERE/usr/bin/EZ-OpenVPN-Toolkit-Web" "$@"
EOF
chmod +x "$APPDIR/AppRun"

cat > "$APPDIR/$APP_NAME.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=$APP_NAME
Exec=$BIN_NAME
Icon=utilities-terminal
Categories=Network;
Terminal=false
EOF

ARCH="${ARCH:-x86_64}"
OUTPUT_PATH="$SCRIPT_DIR/dist/${APP_NAME}-${ARCH}.AppImage"
appimagetool "$APPDIR" "$OUTPUT_PATH"

chmod +x "$OUTPUT_PATH"
echo "Built $OUTPUT_PATH"
