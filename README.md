# EZ OpenVPN Toolkit - Web GUI

This project includes a local Web GUI and can be packaged as a Windows executable.

## What It Does

- Starts a local HTTP server on `127.0.0.1`.
- Opens your default browser automatically.
- Provides UI workflows for:
- server initialization
- client creation/revocation
- package generation (Windows/Linux/FlexEdge)

## Run In Python

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

Output:

- `dist\EZ-OpenVPN-Toolkit-Web.exe`

Behavior:

- Runs as a windowed app (no console window).
- Starts the local server.
- Opens your default browser to the Web GUI.

## Distribute

You can distribute the generated `.exe` from `dist`.

Data (clients, server config, certificates, logs) is stored relative to where the app runs.
