# EZ OpenVPN Toolkit - Web GUI

This project includes a local Web GUI and can be packaged for Windows and Linux.

## What It Does

- Starts a local HTTP server on `127.0.0.1`.
- Opens your default browser automatically.
- Provides UI workflows for:
- server initialization
- client creation/revocation
- package generation (Windows/Linux/FlexEdge)

## Run In Python

Install Python build dependencies first:

```bash
python -m pip install -r requirements.txt
```

From this folder:

```powershell
python web_app.py
```

The app will auto-open in your browser at a local URL similar to:

`http://127.0.0.1:8765/`

## Build Windows Executable

Use the provided build script:

```powershell
powershell -ExecutionPolicy Bypass -File .\build_web_gui_exe.ps1
```

Or use the unified build script:

```bash
./build_web_gui.sh windows
```

Output:

- `dist\EZ-OpenVPN-Toolkit-Web.exe`

Behavior:

- Runs as a windowed app (no console window).
- Starts the local server.
- Opens your default browser to the Web GUI.

## Build Linux Executable

Use the Linux build script:

```bash
./build_web_gui_linux.sh
```

Or use the unified build script:

```bash
./build_web_gui.sh linux
```

Output:

- `dist/EZ-OpenVPN-Toolkit-Web`

Behavior:

- Starts the local server.
- Opens your default browser to the Web GUI.

## Build Linux AppImage

Build from the Linux executable:

```bash
./build_web_gui_appimage.sh
```

Or use the unified build script:

```bash
./build_web_gui.sh appimage
```

Output:

- `dist/EZ-OpenVPN-Toolkit-Web-x86_64.AppImage`

Notes:

- Build on Linux for Linux targets.
- `appimagetool` must be installed on the build machine.

## Unified Build Command

Use one command that auto-selects a sensible default target:

```bash
./build_web_gui.sh
```

Build with cleanup first:

```bash
./build_web_gui.sh --clean
```

Build a specific target with cleanup first:

```bash
./build_web_gui.sh --clean appimage
```

Default behavior:

- Linux/macOS: builds Linux executable
- Windows environments with PowerShell: builds Windows `.exe`

## Distribute

You can distribute the generated executable or AppImage from `dist`.

Data (clients, server config, certificates, logs) is stored relative to where the app runs.
