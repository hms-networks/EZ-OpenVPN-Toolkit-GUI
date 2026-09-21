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

APPIMAGE_TOOL="${APPIMAGE_TOOL:-}"

if [[ -z "$APPIMAGE_TOOL" ]] && command -v appimagetool >/dev/null 2>&1; then
  APPIMAGE_TOOL="$(command -v appimagetool)"
fi

if [[ -z "$APPIMAGE_TOOL" && -x "$SCRIPT_DIR/.tools/appimagetool.AppImage" ]]; then
  APPIMAGE_TOOL="$SCRIPT_DIR/.tools/appimagetool.AppImage"
fi

if [[ -z "$APPIMAGE_TOOL" ]]; then
  echo "appimagetool is required to create an AppImage." >&2
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
APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGE_TOOL" "$APPDIR" "$OUTPUT_PATH"

chmod +x "$OUTPUT_PATH"
echo "Built $OUTPUT_PATH"
