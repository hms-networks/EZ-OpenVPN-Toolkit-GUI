#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

usage() {
  cat <<'EOF'
Usage:
  ./build_web_gui.sh [--clean] [windows|linux|appimage]

Defaults:
  - On Linux/macOS: linux
  - On Windows environments with PowerShell: windows

Targets:
  windows   Build Windows .exe using build_web_gui_exe.ps1
  linux     Build Linux executable using build_web_gui_linux.sh
  appimage  Build Linux AppImage using build_web_gui_appimage.sh

Options:
  --clean   Remove build artifacts before building (build/, dist/, AppDir/)
EOF
}

CLEAN=0
TARGET="auto"

for arg in "$@"; do
  case "$arg" in
    --clean)
      CLEAN=1
      ;;
    windows|linux|appimage|auto)
      TARGET="$arg"
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg"
      usage
      exit 2
      ;;
  esac
done

clean_artifacts() {
  local path
  for path in "$SCRIPT_DIR/build" "$SCRIPT_DIR/dist" "$SCRIPT_DIR/AppDir"; do
    if [[ -e "$path" ]]; then
      rm -rf "$path"
    fi
  done
}

run_windows_build() {
  local ps1_script="$SCRIPT_DIR/build_web_gui_exe.ps1"

  if command -v powershell >/dev/null 2>&1; then
    powershell -ExecutionPolicy Bypass -File "$ps1_script"
    return
  fi

  if command -v pwsh >/dev/null 2>&1; then
    pwsh -ExecutionPolicy Bypass -File "$ps1_script"
    return
  fi

  if command -v powershell.exe >/dev/null 2>&1; then
    powershell.exe -ExecutionPolicy Bypass -File "$ps1_script"
    return
  fi

  echo "PowerShell was not found. Cannot run Windows build target."
  exit 1
}

if [[ "$CLEAN" -eq 1 ]]; then
  clean_artifacts
fi

case "$TARGET" in
  windows)
    run_windows_build
    ;;
  linux)
    "$SCRIPT_DIR/build_web_gui_linux.sh"
    ;;
  appimage)
    "$SCRIPT_DIR/build_web_gui_appimage.sh"
    ;;
  auto)
    case "$(uname -s)" in
      Linux|Darwin)
        "$SCRIPT_DIR/build_web_gui_linux.sh"
        ;;
      MINGW*|MSYS*|CYGWIN*)
        run_windows_build
        ;;
      *)
        # Prefer Windows build if PowerShell is available; otherwise Linux build.
        if command -v powershell >/dev/null 2>&1 || command -v pwsh >/dev/null 2>&1 || command -v powershell.exe >/dev/null 2>&1; then
          run_windows_build
        else
          "$SCRIPT_DIR/build_web_gui_linux.sh"
        fi
        ;;
    esac
    ;;
  *)
    echo "Unknown target: $TARGET"
    usage
    exit 2
    ;;
esac
