# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# Software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Local browser UI for the EZ OpenVPN Toolkit.

Run with:
    python web_app.py

Build a Windows executable with PyInstaller:
    pyinstaller --onefile --name EZ-OpenVPN-Toolkit-Web web_app.py --add-data "needed_binaries;needed_binaries" --add-data "deploy_ovpn_server_on_win10-11.ps1;." --add-data "deploy_ovpn_server_linux.sh;."
"""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import csv
import io
import json
import logging
import mimetypes
import base64
import html
import os
import posixpath
import re
import secrets
import signal
import socket
import shutil
import subprocess
import sys
import threading
import time
import traceback
import uuid
import webbrowser
import zipfile
import xml.etree.ElementTree as ET
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from ca_setup import setup_ca
from client_manager import list_current_clients, manage_client_creation
from client_revoke import revoke_client
from config import COMMON_DETAILS, get_base_dir
from helpers import create_directory
from logger import setup_logging
from main import (
    load_server_config,
    modify_server_conf_for_flexedge,
    package_server_linux,
    package_server_windows,
    save_server_config,
)
from openvpn_config import generate_server_conf
from server_cert import generate_server_certificates
from subnet_management import (
    get_subnet_by_name,
    load_existing_subnets,
    save_subnet_to_csv,
    validate_subnet,
)


BASE_DIR = get_base_dir()
CLIENTS_DIR = os.path.join(BASE_DIR, "clients")
SUBNETS_CSV = os.path.join(BASE_DIR, "subnets.csv")
APP_INSTANCE_LOCK = os.path.join(BASE_DIR, ".ez_openvpn_toolkit_web.lock")
CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
RESERVED_CLIENT_NAMES = {"server", "ca", "openvpn", "root", "admin"}

CIPHER_OPTIONS = [
    "CAMELLIA-128-CBC",
    "AES-128-CBC",
    "CAMELLIA-192-CBC",
    "AES-192-CBC",
    "CAMELLIA-256-CBC",
    "AES-256-CBC",
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "CHACHA20-POLY1305",
]

JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
_WINDOWS_GUIDE_CACHE: dict[str, object] = {"mtime": None, "payload": None}
_EWON_GUIDE_CACHE: dict[str, object] = {"mtime": None, "payload": None}
_LINUX_GUIDE_CACHE: dict[str, object] = {"mtime": None, "payload": None}
_FLEXEDGE_GUIDE_CACHE: dict[str, object] = {"mtime": None, "payload": None}
_ANYBUS_DEFENDER_GUIDE_CACHE: dict[str, object] = {"mtime": None, "payload": None}

# Single-use CSRF token generated fresh each time the server starts.
_CSRF_TOKEN: str = secrets.token_hex(32)

_MGMT_MAX_OUTPUT_BYTES = 256 * 1024
_IDLE_SHUTDOWN_SECONDS = 90
_LAST_ACTIVITY_TS = time.time()


def _touch_activity() -> None:
    global _LAST_ACTIVITY_TS
    _LAST_ACTIVITY_TS = time.time()


def _json_default(value):
    return str(value)


def _read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    if not length:
        return {}
    raw = handler.rfile.read(length).decode("utf-8")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in request body: {exc}") from exc


def _safe_join(*parts: str) -> str:
    path = os.path.abspath(os.path.join(BASE_DIR, *parts))
    if not (path == BASE_DIR or path.startswith(BASE_DIR + os.sep)):
        raise ValueError("Requested path is outside the toolkit directory.")
    return path


def _resolve_runtime_icon_path() -> str | None:
  # Prefer an icon next to the app, but fall back to the bundled resource.
  icon_names = ("HMS.ico", "hms.ico")
  for icon_name in icon_names:
    disk_path = _safe_join(icon_name)
    if os.path.isfile(disk_path):
      return disk_path

  bundle_dir = getattr(sys, "_MEIPASS", None)
  if bundle_dir:
    for icon_name in icon_names:
      bundled_path = os.path.join(bundle_dir, icon_name)
      if os.path.isfile(bundled_path):
        return bundled_path

  return None


def _resolve_runtime_asset_path(file_name: str) -> str:
  disk_path = os.path.join(BASE_DIR, file_name)
  if os.path.isfile(disk_path):
    return disk_path

  bundle_dir = getattr(sys, "_MEIPASS", None)
  if bundle_dir:
    bundled_path = os.path.join(bundle_dir, file_name)
    if os.path.isfile(bundled_path):
      return bundled_path

  return disk_path


def _validate_client_name(name: str) -> str:
  name = (name or "").strip()
  if not CLIENT_NAME_RE.match(name):
    raise ValueError(
      "Client names may contain letters, numbers, underscore, dash, and dot."
    )
  if name.lower() in RESERVED_CLIENT_NAMES:
    blocked = ", ".join(sorted(RESERVED_CLIENT_NAMES))
    raise ValueError(
      f"Client name is reserved and cannot be used: {name}. Reserved: {blocked}"
    )
  return name


def _certificate_details(payload: dict) -> dict:
    details = dict(COMMON_DETAILS)
    details.update(payload.get("certificate_details") or {})
    details["C"] = str(details.get("C", "")).upper()
    if len(details["C"]) != 2 or not details["C"].isalpha():
        raise ValueError("Country code must be exactly two letters.")
    for key in ["ST", "L", "O", "OU", "email_address"]:
        if not str(details.get(key, "")).strip():
            raise ValueError(f"Certificate field {key} cannot be empty.")
    return details


def _server_details(payload: dict) -> tuple[str, str, str, str, list[str], bool, int | None, int | None]:
    server_address = str(payload.get("server_address", "")).strip()
    port = str(payload.get("port", "")).strip()
    proto = str(payload.get("proto", "udp")).strip().lower()
    data_ciphers = payload.get("data_ciphers") or []
    if not server_address:
        raise ValueError("Server address is required.")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        raise ValueError("Port must be a number between 1 and 65535.")
    if proto not in {"tcp", "udp"}:
        raise ValueError("Protocol must be tcp or udp.")
    data_ciphers = [cipher for cipher in data_ciphers if cipher in CIPHER_OPTIONS]
    if not data_ciphers:
        raise ValueError("Select at least one data cipher.")
    cipher = min(data_ciphers, key=lambda item: CIPHER_OPTIONS.index(item))
    mtu_fix_enabled = bool(payload.get("mtu_fix_enabled", False))
    mssfix_raw = payload.get("mssfix")
    tun_mtu_raw = payload.get("tun_mtu")

    mssfix = None
    tun_mtu = None
    if mtu_fix_enabled:
      if mssfix_raw in (None, "") or tun_mtu_raw in (None, ""):
        raise ValueError("MTU/MSS fix enabled: both mssfix and tun-mtu are required.")
      if not str(mssfix_raw).strip().isdigit() or not str(tun_mtu_raw).strip().isdigit():
        raise ValueError("mssfix and tun-mtu must be positive integer values.")

      mssfix = int(str(mssfix_raw).strip())
      tun_mtu = int(str(tun_mtu_raw).strip())

      if not (900 <= mssfix <= 1460):
        raise ValueError("mssfix must be between 900 and 1460.")
      if not (1200 <= tun_mtu <= 2000):
        raise ValueError("tun-mtu must be between 1200 and 2000.")

    return server_address, port, proto, cipher, data_ciphers, mtu_fix_enabled, mssfix, tun_mtu


def _client_requests(payload: dict, existing_names: set[str]) -> list[dict]:
    clients = payload.get("clients") or []
    cleaned = []
    seen = set()
    for item in clients:
        if isinstance(item, str):
            item = {"name": item}
        name = _validate_client_name(item.get("name", ""))
        if name in seen or name in existing_names:
            raise ValueError(f"Client name already exists: {name}")
        seen.add(name)
        subnet = str(item.get("subnet", "")).strip() or None
        cleaned.append({"name": name, "subnet": subnet})
    if not cleaned:
        raise ValueError("Add at least one client.")
    return cleaned


def _write_server_details(
  server_address,
  port,
  proto,
  cipher,
  data_ciphers,
  mtu_fix_enabled=False,
  mssfix=None,
  tun_mtu=None,
) -> None:
    details = {
        "server_address": server_address,
        "port": port,
        "proto": proto,
        "cipher": cipher,
        "data_ciphers": data_ciphers,
    "mtu_fix_enabled": bool(mtu_fix_enabled),
    "mssfix": mssfix,
    "tun_mtu": tun_mtu,
    }
    with open(os.path.join(BASE_DIR, "server_details.json"), "w", encoding="utf-8") as f:
        json.dump(details, f)


def initialize_from_payload(payload: dict) -> dict:
    _existing_config = load_server_config()
    if _existing_config and _existing_config.get("server_initialized"):
        raise ValueError("Server is already initialized.")

    certificate_details = _certificate_details(payload)
    (
      server_address,
      port,
      proto,
      cipher,
      data_ciphers,
      mtu_fix_enabled,
      mssfix,
      tun_mtu,
    ) = _server_details(payload)
    clients = _client_requests(payload, set())

    existing_subnets = load_existing_subnets(SUBNETS_CSV)
    openvpn_tunnel_subnet = validate_subnet(
        str(payload.get("openvpn_tunnel_subnet", "")).strip(), existing_subnets
    )
    existing_subnets.append(str(openvpn_tunnel_subnet))
    server_lan_raw = str(payload.get("server_lan_subnet", "")).strip()
    server_lan_subnet = None
    if server_lan_raw:
      server_lan_subnet = validate_subnet(server_lan_raw, existing_subnets)
      existing_subnets.append(str(server_lan_subnet))
    for client in clients:
        if client["subnet"]:
            subnet = validate_subnet(client["subnet"], existing_subnets)
            existing_subnets.append(str(subnet))

    server_dir = os.path.join(BASE_DIR, "server")
    ca_dir = os.path.join(BASE_DIR, "ca")
    create_directory(server_dir)
    create_directory(os.path.join(server_dir, "ccd"))

    # Persist certificate defaults early, but mark initialized only on success.
    save_server_config(certificate_details)
    common_details = dict(certificate_details)

    setup_ca(common_details)
    save_subnet_to_csv(SUBNETS_CSV, "openvpn_tunnel_subnet", openvpn_tunnel_subnet)
    if server_lan_subnet:
      save_subnet_to_csv(SUBNETS_CSV, "server_local_private_subnet", server_lan_subnet)

    openssl_cnf_path = os.path.join(ca_dir, "openssl.cnf")
    generate_server_certificates(ca_dir, server_dir, common_details, openssl_cnf_path)
    _write_server_details(
      server_address,
      port,
      proto,
      cipher,
      list(data_ciphers),
      mtu_fix_enabled=mtu_fix_enabled,
      mssfix=mssfix,
      tun_mtu=tun_mtu,
    )

    generate_server_conf(
        os.path.join(server_dir, "server.conf"),
        openvpn_tunnel_subnet,
        os.path.join(ca_dir, "ca.crt"),
        os.path.join(server_dir, "server.crt"),
        os.path.join(server_dir, "server.key"),
        os.path.join(server_dir, "dh.pem"),
        os.path.join(server_dir, "ta.key"),
        os.path.join(ca_dir, "crl.pem"),
        port=port,
        proto=proto,
        cipher=cipher,
        data_ciphers=list(data_ciphers),
        server_lan_subnet=server_lan_subnet,
        ccd_dir="ccd",
        mtu_fix_enabled=mtu_fix_enabled,
        mssfix_value=mssfix,
        tun_mtu_value=tun_mtu,
    )

    created = []
    mtu_fix_enabled = bool(server_details.get("mtu_fix_enabled", False))
    mssfix_value = server_details.get("mssfix")
    tun_mtu_value = server_details.get("tun_mtu")
    for client in clients:
        manage_client_creation(
            client["name"],
            ca_dir,
            common_details,
            openssl_cnf_path,
            os.path.join(server_dir, "server.conf"),
            os.path.join(server_dir, "ccd"),
            openvpn_tunnel_subnet,
            server_address,
            port,
            proto,
            cipher,
            list(data_ciphers),
            client_subnet_input=client["subnet"],
            prompt_for_subnet=False,
        )
        created.append(client["name"])

    with open(os.path.join(BASE_DIR, "client_names.json"), "w", encoding="utf-8") as f:
        json.dump(created, f)

    certificate_details["server_initialized"] = True
    save_server_config(certificate_details)
    return {"created_clients": created}


def _remove_if_exists(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    elif os.path.isfile(path):
        os.remove(path)


def _wipe_generated_state() -> None:
    generated_paths = [
        os.path.join(BASE_DIR, "ca"),
        os.path.join(BASE_DIR, "server"),
        os.path.join(BASE_DIR, "clients"),
        os.path.join(BASE_DIR, "subnets.csv"),
        os.path.join(BASE_DIR, "server_config.json"),
        os.path.join(BASE_DIR, "server_details.json"),
        os.path.join(BASE_DIR, "client_names.json"),
        os.path.join(BASE_DIR, "OpenVPN_Server_Windows.zip"),
        os.path.join(BASE_DIR, "OpenVPN_Server_Linux.zip"),
        os.path.join(BASE_DIR, "OpenVPN_Server_FlexEdge.zip"),
        os.path.join(BASE_DIR, "OpenVPN_Server_Anybus_Defender.zip"),
        os.path.join(BASE_DIR, "temp_flexedge_deploy"),
    ]
    for path in generated_paths:
        _remove_if_exists(path)


def reinitialize_from_payload(payload: dict) -> dict:
    _wipe_generated_state()
    return initialize_from_payload(payload)


def _refresh_server_packages_after_crl_change() -> dict:
  targets = [
    ("windows", "OpenVPN_Server_Windows.zip", package_server_windows),
    ("linux", "OpenVPN_Server_Linux.zip", package_server_linux),
    ("flexedge", "OpenVPN_Server_FlexEdge.zip", package_server_flexedge_web),
    ("anybus_defender", "OpenVPN_Server_Anybus_Defender.zip", package_server_anybus_defender),
  ]
  refreshed_files = []
  failures = []

  for target, filename, package_func in targets:
    try:
      # Keep client/revoke job output concise by suppressing packaging chatter.
      with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        package_func()
      package_path = os.path.join(BASE_DIR, filename)
      if os.path.exists(package_path):
        refreshed_files.append(os.path.relpath(package_path, BASE_DIR))
    except Exception as exc:
      failures.append({"target": target, "error": str(exc)})

  warning = (
    "CRL changed. Redeploy an updated server package on your OpenVPN host "
    "before using newly created clients or expecting revocations to apply."
  )
  if failures:
    failed_targets = ", ".join(item["target"] for item in failures)
    warning = (
      warning
      + f" Automatic package refresh failed for: {failed_targets}. "
      + "Use the Server ZIP buttons to rebuild those packages."
    )

  return {
    "files": refreshed_files,
    "failures": failures,
    "warning": warning,
  }


def add_clients_from_payload(payload: dict) -> dict:
    details_path = os.path.join(BASE_DIR, "server_details.json")
    if not os.path.exists(details_path):
        raise ValueError("Server details not found. Initialize the server first.")
    with open(details_path, "r", encoding="utf-8") as f:
        server_details = json.load(f)
    certificate_details = load_server_config()
    if not certificate_details:
        raise ValueError("Certificate details not found. Initialize the server first.")
    certificate_details.pop("server_initialized", None)

    clients = _client_requests(payload, set(list_current_clients()))
    existing_subnets = load_existing_subnets(SUBNETS_CSV)
    for client in clients:
        if client["subnet"]:
            subnet = validate_subnet(client["subnet"], existing_subnets)
            existing_subnets.append(str(subnet))

    openvpn_tunnel_subnet = get_subnet_by_name(SUBNETS_CSV, "openvpn_tunnel_subnet")
    if not openvpn_tunnel_subnet:
        raise ValueError("OpenVPN tunnel subnet not found. Initialize the server first.")

    created = []
    for client in clients:
        manage_client_creation(
            client["name"],
            os.path.join(BASE_DIR, "ca"),
            certificate_details,
            os.path.join(BASE_DIR, "ca", "openssl.cnf"),
            os.path.join(BASE_DIR, "server", "server.conf"),
            os.path.join(BASE_DIR, "server", "ccd"),
            openvpn_tunnel_subnet,
            server_details["server_address"],
            server_details["port"],
            server_details["proto"],
            server_details["cipher"],
            list(server_details["data_ciphers"]),
            client_subnet_input=client["subnet"],
            prompt_for_subnet=False,
            mtu_fix_enabled=mtu_fix_enabled,
            mssfix_value=mssfix_value,
            tun_mtu_value=tun_mtu_value,
        )
        created.append(client["name"])

    names_path = os.path.join(BASE_DIR, "client_names.json")
    if os.path.exists(names_path):
        with open(names_path, "r", encoding="utf-8") as f:
            names = json.load(f)
    else:
        names = []
    names.extend(name for name in created if name not in names)
    with open(names_path, "w", encoding="utf-8") as f:
        json.dump(names, f)

    refresh = _refresh_server_packages_after_crl_change()
    return {
      "created_clients": created,
      "crl_updated": True,
      "server_packages_refreshed": refresh["files"],
      "package_refresh_failures": refresh["failures"],
      "warning": refresh["warning"],
    }


def revoke_from_payload(payload: dict) -> dict:
    client_name = _validate_client_name(payload.get("client_name", ""))
    if client_name not in list_current_clients():
        raise ValueError(f"Client not found: {client_name}")
    revoke_client(
        client_name,
        os.path.join(BASE_DIR, "ca"),
        os.path.join(BASE_DIR, "ca", "openssl.cnf"),
        SUBNETS_CSV,
    )

    refresh = _refresh_server_packages_after_crl_change()
    return {
      "revoked_client": client_name,
      "crl_updated": True,
      "server_packages_refreshed": refresh["files"],
      "package_refresh_failures": refresh["failures"],
      "warning": refresh["warning"],
    }


def package_from_payload(payload: dict) -> dict:
    target = payload.get("target")
    before = set(_known_downloads())
    if target == "windows":
      package_server_windows()
    elif target == "linux":
      package_server_linux()
    elif target == "flexedge":
      package_server_flexedge_web()
    elif target == "anybus_defender":
      package_server_anybus_defender()
    else:
      raise ValueError("Unknown package target.")
    after = set(_known_downloads())
    created = sorted(after - before)
    return {"files": created or sorted(after)}


def package_client_ewon_from_payload(payload: dict) -> dict:
    client_name = _validate_client_name(payload.get("client_name", ""))
    if client_name not in list_current_clients():
        raise ValueError(f"Client not found: {client_name}")

    client_dir = os.path.join(CLIENTS_DIR, client_name)
    client_ovpn_path = os.path.join(client_dir, f"{client_name}.ovpn")
    ta_key_path = os.path.join(BASE_DIR, "server", "ta.key")
    if not os.path.exists(client_ovpn_path):
        raise ValueError(f"Client OVPN file not found: {client_ovpn_path}")
    if not os.path.exists(ta_key_path):
        raise ValueError("Server ta.key not found. Reinitialize or repair server certificates first.")

    with open(client_ovpn_path, "r", encoding="utf-8") as f:
        source = f.read()

    # Ewon Cosy+/Flexy: use external ta.key reference instead of inline <tls-auth> block.
    converted = re.sub(r"(?is)<tls-auth>.*?</tls-auth>", "", source)
    converted = re.sub(r"(?im)^\s*key-direction\s+\d+\s*$", "", converted)
    converted = re.sub(r"(?im)^\s*tls-auth\s+.*$", "", converted)
    converted = converted.rstrip() + "\n" + "tls-auth /usr/ta.key\n"

    zip_name = f"ewon_flexy-cosy_deploy__{client_name}.zip"
    zip_path = os.path.join(client_dir, zip_name)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.writestr(f"{client_name}.ovpn", converted)
        zipf.write(ta_key_path, arcname="ta.key")

    return {
        "client_name": client_name,
        "file": os.path.relpath(zip_path, BASE_DIR),
    }


def package_server_flexedge_web() -> None:
    server_dir = os.path.join(BASE_DIR, "server")
    if not os.path.exists(server_dir):
        raise ValueError("Server directory not found. Initialize the server first.")
    temp_dir = os.path.join(BASE_DIR, "temp_flexedge_deploy")
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir, exist_ok=True)
    temp_server_dir = os.path.join(temp_dir, "server")
    shutil.copytree(server_dir, temp_server_dir)
    server_conf_path = os.path.join(temp_server_dir, "server.conf")
    modify_server_conf_for_flexedge(server_conf_path)
    shutil.copy(server_conf_path, os.path.join(temp_server_dir, "server.ovpn"))
    files_for_sdcard_dir = os.path.join(temp_dir, "files_for_sdcard")
    os.makedirs(files_for_sdcard_dir, exist_ok=True)
    for filename in ["ipp.txt", "openvpn-status.log", "openvpn.log"]:
        shutil.copy(os.path.join(temp_server_dir, filename), files_for_sdcard_dir)
    shutil.copytree(
        os.path.join(temp_server_dir, "ccd"),
        os.path.join(files_for_sdcard_dir, "ccd"),
    )
    zip_filename = os.path.join(BASE_DIR, "OpenVPN_Server_FlexEdge.zip")
    shutil.make_archive(zip_filename[:-4], "zip", temp_dir)
    shutil.rmtree(temp_dir, ignore_errors=True)


def package_server_anybus_defender() -> None:
    ca_dir = os.path.join(BASE_DIR, "ca")
    server_dir = os.path.join(BASE_DIR, "server")
    if not os.path.exists(ca_dir) or not os.path.exists(server_dir):
        raise ValueError("Server/CA directories not found. Initialize the server first.")

    files_to_zip = [
        (os.path.join(ca_dir, "ca.crt"), "ca.crt"),
        (os.path.join(ca_dir, "ca.key"), "ca.key"),
        (os.path.join(server_dir, "server.crt"), "server.crt"),
        (os.path.join(server_dir, "server.key"), "server.key"),
        (os.path.join(ca_dir, "crl.pem"), "crl.pem"),
        (os.path.join(server_dir, "ta.key"), "ta.key"),
    ]

    missing = [src for src, _ in files_to_zip if not os.path.exists(src)]
    if missing:
        missing_names = ", ".join(os.path.basename(path) for path in missing)
        raise ValueError(f"Missing required files for Anybus Defender package: {missing_names}")

    zip_path = os.path.join(BASE_DIR, "OpenVPN_Server_Anybus_Defender.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        for source_path, arcname in files_to_zip:
            zipf.write(source_path, arcname=arcname)


def _known_downloads() -> list[str]:
    files = []
    for name in [
        "OpenVPN_Server_Windows.zip",
        "OpenVPN_Server_Linux.zip",
        "OpenVPN_Server_FlexEdge.zip",
        "OpenVPN_Server_Anybus_Defender.zip",
    ]:
        path = os.path.join(BASE_DIR, name)
        if os.path.exists(path):
            files.append(path)
    if os.path.isdir(CLIENTS_DIR):
        for root, _, names in os.walk(CLIENTS_DIR):
            for name in names:
                if name.lower().endswith((".zip", ".ovpn")):
                    files.append(os.path.join(root, name))
    return files


def windows_guide_payload() -> dict:
    guide_path = _resolve_runtime_asset_path("Deploy Server Package to Windows.docx")
    mtime = os.path.getmtime(guide_path) if os.path.exists(guide_path) else None
    cached = _WINDOWS_GUIDE_CACHE.get("payload")
    if cached and _WINDOWS_GUIDE_CACHE.get("mtime") == mtime:
        return cached

    ns = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    }

    payload = _parse_docx_guide(guide_path, "Deploy Server Package to Windows", ns)
    _WINDOWS_GUIDE_CACHE["mtime"] = mtime
    _WINDOWS_GUIDE_CACHE["payload"] = payload
    return payload


def _parse_docx_guide(guide_path: str, title: str, ns: dict) -> dict:
    """Helper to parse docx guides with bullet point support."""
    if not os.path.exists(guide_path):
        raise ValueError(f"Guide document not found: {os.path.basename(guide_path)}")

    rel_map: dict[str, str] = {}
    blocks: list[str] = []

    with zipfile.ZipFile(guide_path, "r") as zf:
        if "word/_rels/document.xml.rels" in zf.namelist():
            rels_root = ET.fromstring(zf.read("word/_rels/document.xml.rels"))
            for rel in rels_root.findall("rel:Relationship", ns):
                rid = rel.attrib.get("Id")
                target = rel.attrib.get("Target")
                if rid and target:
                    rel_map[rid] = target

        doc_root = ET.fromstring(zf.read("word/document.xml"))
        body = doc_root.find("w:body", ns)
        if body is None:
            raise ValueError("Guide document is missing content.")

        def add_image_by_rid(rid: str) -> None:
            target = rel_map.get(rid)
            if not target:
                return
            media_path = posixpath.normpath(posixpath.join("word", target))
            if not media_path.startswith("word/"):
                return
            if media_path not in zf.namelist():
                return
            image_bytes = zf.read(media_path)
            ext = os.path.splitext(media_path)[1].lower()
            mime = {
                ".png": "image/png",
                ".jpg": "image/jpeg",
                ".jpeg": "image/jpeg",
                ".gif": "image/gif",
                ".bmp": "image/bmp",
                ".webp": "image/webp",
                ".tif": "image/tiff",
                ".tiff": "image/tiff",
            }.get(ext, "application/octet-stream")
            encoded = base64.b64encode(image_bytes).decode("ascii")
            blocks.append(f'<img src="data:{mime};base64,{encoded}" alt="Deployment guide image">')

        for node in list(body):
            if node.tag == f"{{{ns['w']}}}p":
                text = "".join((t.text or "") for t in node.findall(".//w:t", ns)).strip()
                if text:
                    # Check if paragraph has bullet formatting (w:numPr)
                    pPr = node.find(f"w:pPr", ns)
                    has_bullet = pPr is not None and pPr.find(f"w:numPr", ns) is not None
                    if has_bullet:
                        blocks.append(f"<p>• {html.escape(text)}</p>")
                    else:
                        blocks.append(f"<p>{html.escape(text)}</p>")
                for blip in node.findall(".//a:blip", ns):
                    rid = blip.attrib.get(f"{{{ns['r']}}}embed")
                    if rid:
                        add_image_by_rid(rid)
            elif node.tag == f"{{{ns['w']}}}tbl":
                for row in node.findall(".//w:tr", ns):
                    cells = [
                        "".join((t.text or "") for t in cell.findall(".//w:t", ns)).strip()
                        for cell in row.findall("w:tc", ns)
                    ]
                    if any(cells):
                        blocks.append(f"<p>{html.escape(' | '.join(cells))}</p>")
                for blip in node.findall(".//a:blip", ns):
                    rid = blip.attrib.get(f"{{{ns['r']}}}embed")
                    if rid:
                        add_image_by_rid(rid)

    return {
        "title": title,
        "html": "\n".join(blocks) if blocks else "<p>No guide content found.</p>",
    }


def ewon_guide_payload() -> dict:
    guide_path = _resolve_runtime_asset_path("Deploy Client Package to Cosy+_Flexy.docx")
    mtime = os.path.getmtime(guide_path) if os.path.exists(guide_path) else None
    cached = _EWON_GUIDE_CACHE.get("payload")
    if cached and _EWON_GUIDE_CACHE.get("mtime") == mtime:
        return cached

    ns = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    }

    payload = _parse_docx_guide(guide_path, "Deploy Client Package to Cosy+/Flexy", ns)
    _EWON_GUIDE_CACHE["mtime"] = mtime
    _EWON_GUIDE_CACHE["payload"] = payload
    return payload


def linux_guide_payload() -> dict:
    guide_path = _resolve_runtime_asset_path("Deploy Server Package to Linux.docx")
    mtime = os.path.getmtime(guide_path) if os.path.exists(guide_path) else None
    cached = _LINUX_GUIDE_CACHE.get("payload")
    if cached and _LINUX_GUIDE_CACHE.get("mtime") == mtime:
        return cached

    ns = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    }

    payload = _parse_docx_guide(guide_path, "Deploy Server Package to Linux", ns)
    _LINUX_GUIDE_CACHE["mtime"] = mtime
    _LINUX_GUIDE_CACHE["payload"] = payload
    return payload


def flexedge_guide_payload() -> dict:
    guide_path = _resolve_runtime_asset_path("Deploy Server Package to FlexEdge.docx")
    mtime = os.path.getmtime(guide_path) if os.path.exists(guide_path) else None
    cached = _FLEXEDGE_GUIDE_CACHE.get("payload")
    if cached and _FLEXEDGE_GUIDE_CACHE.get("mtime") == mtime:
        return cached

    ns = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    }

    payload = _parse_docx_guide(guide_path, "Deploy Server Package to FlexEdge", ns)
    _FLEXEDGE_GUIDE_CACHE["mtime"] = mtime
    _FLEXEDGE_GUIDE_CACHE["payload"] = payload
    return payload


def anybus_defender_guide_payload() -> dict:
    guide_path = _resolve_runtime_asset_path("Deploy Server Setup to Anybus Defender.docx")
    mtime = os.path.getmtime(guide_path) if os.path.exists(guide_path) else None
    cached = _ANYBUS_DEFENDER_GUIDE_CACHE.get("payload")
    if cached and _ANYBUS_DEFENDER_GUIDE_CACHE.get("mtime") == mtime:
        return cached

    ns = {
        "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
        "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
        "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
        "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
    }

    payload = _parse_docx_guide(guide_path, "Deploy Server Setup to Anybus Defender", ns)
    _ANYBUS_DEFENDER_GUIDE_CACHE["mtime"] = mtime
    _ANYBUS_DEFENDER_GUIDE_CACHE["payload"] = payload
    return payload


def _subnets() -> list[dict]:
    if not os.path.exists(SUBNETS_CSV):
        return []
    import csv

    with open(SUBNETS_CSV, "r", newline="") as f:
        return list(csv.DictReader(f))


def _read_server_details() -> dict:
    details_path = os.path.join(BASE_DIR, "server_details.json")
    if os.path.exists(details_path):
        with open(details_path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def status_payload() -> dict:
    config = load_server_config() or {}
    with JOBS_LOCK:
        initializing = any(
            job.get("status") == "running"
            and job.get("label") == "Initialize server"
            for job in JOBS.values()
        )
    downloads = [
        {
            "name": os.path.relpath(path, BASE_DIR),
            "path": os.path.relpath(path, BASE_DIR),
            "size": os.path.getsize(path),
        }
        for path in _known_downloads()
    ]
    return {
        "initialized": bool(config.get("server_initialized")),
        "initializing": initializing,
        "clients": list_current_clients(),
        "subnets": _subnets(),
        "server_details": _read_server_details(),
        "certificate_details": {key: config.get(key) for key in COMMON_DETAILS},
        "downloads": downloads,
        "ciphers": CIPHER_OPTIONS,
    }


def _recv_management_text(
    sock: socket.socket, total_timeout: float = 2.0, idle_timeout: float = 0.25
) -> str:
    """Read management-interface output until the socket is idle or timeout."""
    chunks: list[str] = []
    byte_count = 0
    start = time.time()
    last_data = start
    while True:
        now = time.time()
        if now - start >= total_timeout:
            break
        if chunks and (now - last_data) >= idle_timeout:
            break
        try:
            sock.settimeout(idle_timeout)
            data = sock.recv(4096)
        except socket.timeout:
            continue
        if not data:
            break
        byte_count += len(data)
        if byte_count > _MGMT_MAX_OUTPUT_BYTES:
            chunks.append("\n... output truncated ...\n")
            break
        chunks.append(data.decode("utf-8", errors="replace"))
        last_data = time.time()
    return "".join(chunks).strip()


def _parse_status3(response_text: str) -> dict:
  clients = []
  routes = []
  stats = []

  def _parse_row(line: str) -> list[str]:
    # OpenVPN management "status 3" is typically tab-delimited.
    if "\t" in line:
      return [part.strip() for part in line.split("\t")]
    # Keep CSV fallback for other builds/variants.
    return next(csv.reader([line]))

  for raw_line in response_text.splitlines():
    line = raw_line.strip()
    if not line:
      continue

    row = _parse_row(line)
    if not row:
      continue

    tag = row[0]
    if tag == "CLIENT_LIST":
      clients.append(
        {
          "common_name": row[1] if len(row) > 1 else "",
          "real_address": row[2] if len(row) > 2 else "",
          "virtual_address": row[3] if len(row) > 3 else "",
          "bytes_received": int(row[5]) if len(row) > 5 and row[5].isdigit() else 0,
          "bytes_sent": int(row[6]) if len(row) > 6 and row[6].isdigit() else 0,
          "connected_since": row[8] if len(row) > 8 else "",
        }
      )
    elif tag == "ROUTING_TABLE":
      routes.append(
        {
          "virtual_address": row[1] if len(row) > 1 else "",
          "common_name": row[2] if len(row) > 2 else "",
          "real_address": row[3] if len(row) > 3 else "",
          "last_ref": row[5] if len(row) > 5 else "",
        }
      )
    elif tag == "GLOBAL_STATS":
      stats.append(
        {
          "name": row[1] if len(row) > 1 else "",
          "value": row[2] if len(row) > 2 else "",
        }
      )

  return {"clients": clients, "routes": routes, "global_stats": stats}


class ManagementSession:
    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._host = ""
        self._port = 0
        self._banner = ""
        self._lock = threading.Lock()
        self._command_lock = threading.Lock()
        self._response_cv = threading.Condition()
        self._response_lines: list[str] = []
        self._response_done = False
        self._last_response_data_ts = 0.0
        self._events: list[dict] = []
        self._event_id = 0
        self._reader_stop = threading.Event()
        self._reader_thread: threading.Thread | None = None

    def _push_event(self, line: str) -> None:
        line = line.strip()
        if not line:
            return
        if ":" in line:
            event_type = line.split(":", 1)[0].lstrip(">")
        else:
            event_type = "INFO"
        self._event_id += 1
        self._events.append(
            {
                "id": self._event_id,
                "ts": time.time(),
                "type": event_type,
                "line": line,
            }
        )
        if len(self._events) > 1000:
            self._events = self._events[-1000:]

    def _reader(self) -> None:
        sock = self._sock
        if not sock:
            return
        buffer = ""
        while not self._reader_stop.is_set():
            try:
                sock.settimeout(0.5)
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buffer += chunk.decode("utf-8", errors="replace")
            while "\n" in buffer:
                raw_line, buffer = buffer.split("\n", 1)
                line = raw_line.rstrip("\r")
                if not line:
                    continue
                if line.startswith(">"):
                    with self._response_cv:
                        self._push_event(line)
                    continue
                with self._response_cv:
                    if self._command_lock.locked():
                        self._response_lines.append(line)
                        self._last_response_data_ts = time.time()
                        if line == "END" or line.startswith("SUCCESS:") or line.startswith("ERROR:"):
                            self._response_done = True
                        self._response_cv.notify_all()
                    else:
                        self._push_event(line)

        with self._response_cv:
            self._push_event(">INFO:Management interface disconnected")
            self._response_done = True
            self._response_cv.notify_all()
        self._disconnect_nolock()

    def _disconnect_nolock(self) -> None:
        sock = self._sock
        self._sock = None
        self._host = ""
        self._port = 0
        self._banner = ""
        self._reader_stop.set()
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    def connect(self, host: str, port: int, password: str = "") -> dict:
        with self._lock:
            self._disconnect_nolock()
            sock = socket.create_connection((host, port), timeout=3.0)
            banner = _recv_management_text(sock, total_timeout=1.5, idle_timeout=0.2)
            if "ENTER PASSWORD:" in banner.upper():
                if not password:
                    sock.close()
                    raise ValueError("Management interface requested a password.")
                sock.sendall((password + "\n").encode("utf-8"))
                auth_reply = _recv_management_text(sock, total_timeout=1.5, idle_timeout=0.2)
                banner = "\n".join(part for part in [banner, auth_reply] if part).strip()
                if "ERROR:" in auth_reply.upper() and "SUCCESS:" not in auth_reply.upper():
                    sock.close()
                    raise ValueError("Management password was rejected.")

            self._sock = sock
            self._host = host
            self._port = port
            self._banner = banner
            self._reader_stop.clear()
            self._reader_thread = threading.Thread(target=self._reader, daemon=True)
            self._reader_thread.start()
            self._push_event(">INFO:Connected to management interface")
            return self.status()

    def disconnect(self) -> dict:
        with self._lock:
            self._disconnect_nolock()
            return {"connected": False}

    def status(self) -> dict:
        connected = self._sock is not None
        return {
            "connected": connected,
            "host": self._host if connected else "",
            "port": self._port if connected else "",
            "banner": self._banner if connected else "",
        }

    def command(self, command: str, timeout: float = 4.0) -> str:
        if "\n" in command or "\r" in command:
            raise ValueError("Management command must be a single line.")
        command = command.strip()
        if not command:
            raise ValueError("Management command is required.")
        sock = self._sock
        if not sock:
            raise ValueError("Management interface is not connected.")

        with self._command_lock:
            with self._response_cv:
                self._response_lines = []
                self._response_done = False
                self._last_response_data_ts = 0.0
            try:
                sock.sendall((command + "\n").encode("utf-8"))
            except OSError as exc:
                self.disconnect()
                raise ValueError(f"Failed to send command: {exc}") from exc

            end = time.time() + timeout
            with self._response_cv:
                while True:
                    now = time.time()
                    if self._response_done:
                        break
                    if self._response_lines and self._last_response_data_ts and (now - self._last_response_data_ts) > 0.35:
                        break
                    remaining = end - now
                    if remaining <= 0:
                        break
                    self._response_cv.wait(timeout=min(0.25, remaining))
                lines = list(self._response_lines)

        if not lines:
            return ""
        if lines[-1] == "END":
            lines = lines[:-1]
        return "\n".join(lines).strip()

    def events_since(self, since_id: int) -> list[dict]:
        with self._response_cv:
            return [evt for evt in self._events if evt["id"] > since_id]


MGMT_SESSION = ManagementSession()

MGMT_ALLOWED_COMMANDS = {
  "status",
  "state",
  "log",
  "bytecount",
  "kill",
  "version",
  "help",
  "verb",
  "mute",
  "pid",
}


def _assert_management_command_allowed(command: str) -> None:
    head = command.strip().split(" ", 1)[0].lower()
    if head not in MGMT_ALLOWED_COMMANDS:
        allowed = ", ".join(sorted(MGMT_ALLOWED_COMMANDS))
        raise ValueError(f"Command '{head}' is not allowed. Allowed: {allowed}")


def management_connect_from_payload(payload: dict) -> dict:
    host = str(payload.get("host", "")).strip() or "127.0.0.1"
    port_raw = str(payload.get("port", "7505")).strip()
    password = str(payload.get("password", ""))
    if not port_raw.isdigit() or not (1 <= int(port_raw) <= 65535):
        raise ValueError("Management port must be a number between 1 and 65535.")
    return MGMT_SESSION.connect(host, int(port_raw), password)


def management_command_from_payload(payload: dict) -> dict:
    command = str(payload.get("command", "")).strip()
    _assert_management_command_allowed(command)
    response = MGMT_SESSION.command(command)
    return {
        "command": command,
        "response": response,
        "status": MGMT_SESSION.status(),
    }


def management_clients_payload() -> dict:
    response = MGMT_SESSION.command("status 3", timeout=5.0)
    parsed = _parse_status3(response)
    return {"raw": response, **parsed}


def management_kill_from_payload(payload: dict) -> dict:
    target = str(payload.get("target", "")).strip()
    if not target:
        raise ValueError("Target common-name or IP:port is required.")
    response = MGMT_SESSION.command(f"kill {target}")
    return {"target": target, "response": response}


def management_realtime_from_payload(payload: dict) -> dict:
    enable_state = bool(payload.get("state_on", True))
    enable_log = bool(payload.get("log_on", True))
    bytecount_interval = int(payload.get("bytecount_interval", 5) or 0)
    commands = [
        "state on" if enable_state else "state off",
        "log on" if enable_log else "log off",
        f"bytecount {bytecount_interval}" if bytecount_interval > 0 else "bytecount 0",
    ]
    outputs = []
    for cmd in commands:
        outputs.append({"command": cmd, "response": MGMT_SESSION.command(cmd)})
    return {"results": outputs}


def start_job(label: str, func, payload: dict) -> str:
    job_id = uuid.uuid4().hex
    with JOBS_LOCK:
        JOBS[job_id] = {
            "id": job_id,
            "label": label,
            "status": "running",
            "started_at": time.time(),
            "finished_at": None,
            "output": "",
            "result": None,
            "error": None,
        }

    def runner():
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
                result = func(payload)
            with JOBS_LOCK:
                JOBS[job_id].update(
                    {
                        "status": "complete",
                        "finished_at": time.time(),
                        "output": stdout.getvalue(),
                        "result": result,
                    }
                )
        except Exception as exc:
            with JOBS_LOCK:
                JOBS[job_id].update(
                    {
                        "status": "failed",
                        "finished_at": time.time(),
                        "output": stdout.getvalue(),
                        "error": f"{exc}\n{traceback.format_exc()}",
                    }
                )

    threading.Thread(target=runner, daemon=True).start()
    return job_id


_JOB_TTL_SECONDS = 3600  # prune finished jobs after 1 hour


def _prune_jobs() -> None:
    while True:
        time.sleep(300)  # check every 5 minutes
        cutoff = time.time() - _JOB_TTL_SECONDS
        with JOBS_LOCK:
            stale = [
                jid for jid, job in JOBS.items()
                if job["status"] in ("complete", "failed")
                and (job["finished_at"] or 0) < cutoff
            ]
            for jid in stale:
                del JOBS[jid]


threading.Thread(target=_prune_jobs, daemon=True).start()


class ToolkitHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        _touch_activity()
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._send_html(INDEX_HTML)
        if parsed.path == "/favicon.ico":
            icon_path = _resolve_runtime_icon_path()
            if icon_path:
                return self._send_file(icon_path, as_attachment=False)
            return self._send_json({"error": "File not found."}, HTTPStatus.NOT_FOUND)
        if parsed.path == "/api/status":
            return self._send_json(status_payload())
        if parsed.path == "/api/management/status":
            return self._send_json(MGMT_SESSION.status())
        if parsed.path == "/api/management/events":
            query = parse_qs(parsed.query)
            since_raw = query.get("since", ["0"])[0]
            since = int(since_raw) if str(since_raw).isdigit() else 0
            return self._send_json({"events": MGMT_SESSION.events_since(since)})
        if parsed.path == "/api/management/clients":
            try:
                return self._send_json(management_clients_payload())
            except Exception as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if parsed.path.startswith("/api/jobs/"):
            job_id = parsed.path.rsplit("/", 1)[-1]
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                return self._send_json({"error": "Job not found."}, HTTPStatus.NOT_FOUND)
            return self._send_json(job)
        if parsed.path == "/api/download":
            query = parse_qs(parsed.query)
            rel_path = query.get("path", [""])[0]
            try:
                file_path = _safe_join(rel_path)
            except ValueError as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
            return self._send_file(file_path)
        if parsed.path == "/api/windows-guide":
          try:
            return self._send_json(windows_guide_payload())
          except Exception as exc:
            return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if parsed.path == "/api/ewon-guide":
          try:
            return self._send_json(ewon_guide_payload())
          except Exception as exc:
            return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if parsed.path == "/api/linux-guide":
          try:
            return self._send_json(linux_guide_payload())
          except Exception as exc:
            return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if parsed.path == "/api/flexedge-guide":
          try:
            return self._send_json(flexedge_guide_payload())
          except Exception as exc:
            return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if parsed.path == "/api/anybus-defender-guide":
          try:
            return self._send_json(anybus_defender_guide_payload())
          except Exception as exc:
            return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        return self._send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)

    def do_POST(self):
        _touch_activity()
        if self.headers.get("X-CSRF-Token") != _CSRF_TOKEN:
            return self._send_json({"error": "Forbidden."}, HTTPStatus.FORBIDDEN)
        path = urlparse(self.path).path
        if path == "/api/app/exit":
            # Diagnostic: write proof file to %TEMP% and next to exe.
            _dbg_content = (
                f"Exit endpoint hit at {time.strftime('%H:%M:%S')}\n"
                f"sys.executable: {sys.executable}\n"
                f"pid: {os.getpid()}  ppid: {os.getppid()}\n"
            )
            for _dbg in [
                os.path.join(os.environ.get("TEMP", "C:\\Temp"), "ez_exit_debug.txt"),
                os.path.join(BASE_DIR, "ez_exit_debug.txt"),
            ]:
                try:
                    with open(_dbg, "w") as _f:
                        _f.write(_dbg_content)
                except Exception:
                    pass
            try:
                _request_app_exit(self.server)
            except Exception as exc:
                trace_msg = (
                    f"[{time.strftime('%H:%M:%S')}] _request_app_exit exception: {exc}\n"
                    f"{traceback.format_exc()}\n"
                )
                for _trace_path in [
                    os.path.join(BASE_DIR, "exit_trace.log"),
                    os.path.join(os.environ.get("TEMP", "C:\\Temp"), "exit_trace.log"),
                ]:
                    with contextlib.suppress(Exception):
                        with open(_trace_path, "a", encoding="utf-8") as _f:
                            _f.write(trace_msg)
                return self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return self._send_json({"ok": True, "message": "Shutting down application."}, HTTPStatus.OK)
        if path == "/api/management/connect":
            try:
                payload = _read_json(self)
                result = management_connect_from_payload(payload)
                return self._send_json(result, HTTPStatus.OK)
            except Exception as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/management/disconnect":
            try:
                return self._send_json(MGMT_SESSION.disconnect(), HTTPStatus.OK)
            except Exception as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/management/command":
            try:
                payload = _read_json(self)
                result = management_command_from_payload(payload)
                return self._send_json(result, HTTPStatus.OK)
            except Exception as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/management/kill":
            try:
                payload = _read_json(self)
                result = management_kill_from_payload(payload)
                return self._send_json(result, HTTPStatus.OK)
            except Exception as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        if path == "/api/management/realtime":
            try:
                payload = _read_json(self)
                result = management_realtime_from_payload(payload)
                return self._send_json(result, HTTPStatus.OK)
            except Exception as exc:
                return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        routes = {
            "/api/initialize": ("Initialize server", initialize_from_payload),
            "/api/reinitialize": ("Re-Initialize server", reinitialize_from_payload),
            "/api/clients": ("Add clients", add_clients_from_payload),
            "/api/revoke": ("Revoke client", revoke_from_payload),
            "/api/package": ("Package files", package_from_payload),
          "/api/package-client-ewon": ("Package client for Ewon", package_client_ewon_from_payload),
        }
        route = routes.get(path)
        if not route:
            return self._send_json({"error": "Not found."}, HTTPStatus.NOT_FOUND)
        try:
            payload = _read_json(self)
            job_id = start_job(route[0], route[1], payload)
            return self._send_json({"job_id": job_id}, HTTPStatus.ACCEPTED)
        except Exception as exc:
            return self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)

    def _send_json(self, data, status=HTTPStatus.OK):
        body = json.dumps(data, default=_json_default).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, html: str):
        html = html.replace("__CSRF_TOKEN__", _CSRF_TOKEN)
        body = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, file_path: str, as_attachment: bool = True):
        if not os.path.exists(file_path) or not os.path.isfile(file_path):
            return self._send_json({"error": "File not found."}, HTTPStatus.NOT_FOUND)
        content_type = mimetypes.guess_type(file_path)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        if as_attachment:
            self.send_header(
                "Content-Disposition",
                f'attachment; filename="{os.path.basename(file_path)}"',
            )
        self.send_header("Content-Length", str(os.path.getsize(file_path)))
        self.end_headers()
        with open(file_path, "rb") as f:
            shutil.copyfileobj(f, self.wfile)


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>EZ OpenVPN Toolkit</title>
  <link rel="icon" href="/favicon.ico" type="image/x-icon">
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --panel-soft: #fbfcfd;
      --ink: #18202a;
      --muted: #626f7f;
      --line: #d9dee6;
      --accent: #116a7b;
      --accent-2: #8a5a12;
      --danger: #a73535;
      --good: #28724f;
      --shadow: 0 1px 2px rgba(20, 28, 38, .08);
    }
    body.dark-theme {
      color-scheme: dark;
      --bg: #11161d;
      --panel: #1b2430;
      --panel-soft: #202b38;
      --ink: #dfe8f0;
      --muted: #9cafc1;
      --line: #344454;
      --accent: #2d8aa0;
      --accent-2: #b2863d;
      --danger: #d45a5a;
      --good: #46a277;
      --shadow: 0 1px 2px rgba(0, 0, 0, .4);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font: 14px/1.45 "Segoe UI", system-ui, sans-serif;
      color: var(--ink);
      background: var(--bg);
    }
    header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      padding: 18px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel);
      position: sticky;
      top: 0;
      z-index: 3;
    }
    h1, h2, h3 { margin: 0; letter-spacing: 0; }
    h1 { font-size: 20px; }
    h2 { font-size: 16px; margin-bottom: 12px; }
    h3 { font-size: 14px; margin: 12px 0 8px; }
    main {
      display: block;
      min-height: calc(100vh - 62px);
    }
    nav {
      border-right: 1px solid var(--line);
      background: var(--panel-soft);
      padding: 16px;
    }
    nav button {
      width: 100%;
      text-align: left;
      margin-bottom: 6px;
      background: transparent;
      color: var(--ink);
    }
    nav button.active {
      background: color-mix(in oklab, var(--accent) 18%, var(--panel));
      color: var(--ink);
    }
    section { display: none; padding: 22px 28px 40px; }
    section.active { display: block; }
    .grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(260px, 1fr));
      gap: 14px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 16px;
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-weight: 600;
      margin: 10px 0 6px;
    }
    input, select {
      width: 100%;
      min-height: 36px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 7px 9px;
      background: var(--panel);
      color: var(--ink);
      font: inherit;
    }
    .input-error {
      border-color: var(--danger) !important;
      box-shadow: 0 0 0 1px rgba(167, 53, 53, 0.25);
    }
    .row {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 10px;
    }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 14px; }
    button, .download {
      border: 1px solid transparent;
      border-radius: 6px;
      padding: 8px 12px;
      background: var(--accent);
      color: #fff;
      font: inherit;
      font-weight: 600;
      cursor: pointer;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      min-height: 36px;
    }
    button.secondary { background: var(--panel-soft); color: var(--ink); border-color: var(--line); }
    button.warn { background: var(--accent-2); }
    button.danger { background: var(--danger); }
    button:disabled { opacity: .55; cursor: not-allowed; }
    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-weight: 600;
    }
    .dot {
      width: 10px;
      height: 10px;
      border-radius: 50%;
      background: var(--danger);
      display: inline-block;
    }
    .dot.ready { background: var(--good); }
    .muted { color: var(--muted); }
    table { border-collapse: collapse; width: 100%; background: var(--panel); }
    th, td { border-bottom: 1px solid var(--line); padding: 8px; text-align: left; }
    th { color: var(--muted); font-size: 12px; text-transform: uppercase; }
    td.action-cell { white-space: nowrap; width: 1%; vertical-align: middle; }
    .action-group { display: inline-flex; align-items: center; gap: 6px; flex-wrap: nowrap; }
    .client-row {
      display: grid;
      grid-template-columns: 1fr 1fr auto;
      gap: 8px;
      align-items: end;
      margin-bottom: 8px;
    }
    pre {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      word-break: break-word;
      overflow: auto;
      background: color-mix(in oklab, var(--bg) 60%, #000 40%);
      color: #dce7ee;
      border-radius: 8px;
      padding: 12px;
      max-height: 260px;
    }
    .checkboxes {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 8px;
      margin-top: 8px;
    }
    .check {
      display: flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 8px;
      font-weight: 500;
    }
    .check input { width: auto; min-height: auto; }
    .mtu-toggle-row {
      display: flex;
      justify-content: center;
      margin-top: 10px;
    }
    .mtu-toggle-label {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin: 0;
      font-weight: 600;
      text-align: center;
    }
    .mtu-toggle-label input[type="checkbox"] {
      width: 18px;
      height: 18px;
      min-height: 18px;
      padding: 0;
      margin: 0;
      accent-color: var(--accent);
      border-radius: 4px;
      flex: 0 0 auto;
    }
    .status-note {
      font-weight: 600;
    }
    .status-note.ok { color: var(--good); }
    .status-note.err { color: var(--danger); }
    .status-note.pending { color: var(--accent-2); }
    .status-note.warn { color: var(--accent-2); }
    .brand {
      display: inline-flex;
      align-items: center;
      gap: 10px;
    }
    .brand img {
      width: 28px;
      height: 28px;
      border-radius: 4px;
      object-fit: contain;
    }
    .stat-cards {
      display: grid;
      grid-template-columns: repeat(3, minmax(150px, 1fr));
      gap: 10px;
      margin: 10px 0;
    }
    .stat-card {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 10px;
      background: var(--panel-soft);
    }
    .stat-card .label { color: var(--muted); font-size: 12px; }
    .stat-card .value { font-size: 18px; font-weight: 700; }
    .progress-wrap {
      width: 100%;
      height: 10px;
      border-radius: 999px;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      overflow: hidden;
    }
    .progress-bar {
      height: 100%;
      width: 0%;
      background: var(--accent);
      transition: width .25s ease;
    }
    .progress-bar.running {
      width: 55%;
      animation: pulse 1.2s ease-in-out infinite;
    }
    .progress-bar.complete { width: 100%; background: var(--good); }
    .progress-bar.failed { width: 100%; background: var(--danger); }
    @keyframes pulse {
      0% { opacity: .55; }
      50% { opacity: 1; }
      100% { opacity: .55; }
    }
    .overlay {
      position: fixed;
      inset: 0;
      display: none;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.7);
      z-index: 50;
    }
    .overlay.show { display: flex; }
    .dialog {
      max-width: 640px;
      width: min(92vw, 640px);
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      box-shadow: var(--shadow);
      padding: 18px;
    }
    .dialog.init-dialog {
      max-width: min(96vw, 1040px);
      width: min(96vw, 1040px);
      max-height: 90vh;
      overflow: auto;
    }
    .dialog.guide-dialog {
      max-width: min(94vw, 960px);
      width: min(94vw, 960px);
      max-height: 88vh;
      overflow: auto;
    }
    .help-btn {
      min-width: 34px;
      width: 34px;
      height: 34px;
      border-radius: 999px;
      padding: 0;
      font-size: 18px;
      font-weight: 700;
      line-height: 1;
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }
    h2.section-heading {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      margin: 0 0 10px;
    }
    .section-help-content p {
      margin: 0 0 10px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .guide-content p {
      margin: 0 0 10px;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .guide-content img {
      display: block;
      max-width: 100%;
      height: auto;
      margin: 10px 0 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    @media (max-width: 820px) {
      main { grid-template-columns: 1fr; }
      nav { border-right: 0; border-bottom: 1px solid var(--line); }
      .grid, .row, .client-row { grid-template-columns: 1fr; }
      header { align-items: flex-start; flex-direction: column; }
    }
  </style>
</head>
<body>
  <header>
    <div>
      <h1 class="brand"><img src="/favicon.ico" alt="HMS logo">EZ OpenVPN Toolkit</h1>
      <div class="muted" id="baseDir"></div>
    </div>
    <div class="actions">
      <button type="button" class="danger" id="exitAppBtn" onclick="exitApp()">Exit App</button>
      <button type="button" class="secondary" id="themeToggle" onclick="toggleTheme()">Dark Mode</button>
      <div class="status"><span class="dot" id="readyDot"></span><span id="readyText">Loading</span></div>
    </div>
  </header>
  <main>
    <div>
      <section id="status" class="active">
        <div class="panel">
          <h2 class="section-heading">Server
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('server')" title="About Server" aria-label="About Server">?</button>
          </h2>
          <div id="serverSummary"></div>
          <div id="crlNotice" class="status-note warn" style="display:none;margin:10px 0;"></div>
          <div id="serverPackageActions" class="actions">
            <button id="packageWindowsBtn" type="button" onclick="packageTarget('windows')">Generate Windows Deployment Package</button>
            <button id="packageWindowsGuideBtn" type="button" class="secondary help-btn" style="display:none;" onclick="openWindowsGuideModal()" title="Open Windows deployment guide" aria-label="Open Windows deployment guide">?</button>
            <button id="packageLinuxBtn" type="button" onclick="packageTarget('linux')">Generate Linux Deployment Package</button>
            <button id="packageLinuxGuideBtn" type="button" class="secondary help-btn" style="display:none;" onclick="openLinuxGuideModal()" title="Open Linux deployment guide" aria-label="Open Linux deployment guide">?</button>
            <button id="packageFlexedgeBtn" type="button" onclick="packageTarget('flexedge')">Generate FlexEdge Deployment Package</button>
            <button id="packageFlexedgeGuideBtn" type="button" class="secondary help-btn" style="display:none;" onclick="openFlexedgeGuideModal()" title="Open FlexEdge deployment guide" aria-label="Open FlexEdge deployment guide">?</button>
            <button id="packageAnybusDefenderBtn" type="button" onclick="packageTarget('anybus_defender')">Generate Anybus Defender Deployment Package</button>
            <button id="packageAnybusDefenderGuideBtn" type="button" class="secondary help-btn" style="display:none;" onclick="openAnybusDefenderGuideModal()" title="Open Anybus Defender deployment guide" aria-label="Open Anybus Defender deployment guide">?</button>
          </div>
        </div>
        <div id="statusReadyArea">
        <div class="panel">
          <h2 class="section-heading">Add Client
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('add_client')" title="About Add Client" aria-label="About Add Client">?</button>
          </h2>
          <div id="addClientsForm"></div>
          <div id="clientActionMessage" class="status-note muted" style="display:none;margin-top:8px;"></div>
          <div id="nameErrorAddClients" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;"></div>
          <div id="subnetErrorAddClients" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;"></div>
          <div class="actions">
            <button id="generateClientBtn" onclick="addClients()">Generate Client</button>
          </div>
        </div>
        <div>
          <div class="panel">
            <h2 class="section-heading">Clients
              <button type="button" class="secondary help-btn" onclick="openSectionHelp('clients')" title="About Clients" aria-label="About Clients">?</button>
            </h2>
            <table>
              <thead><tr><th>Client</th><th>Packages</th><th>Action</th></tr></thead>
              <tbody id="clientTable"></tbody>
            </table>
          </div>
          <div class="panel" style="margin-top:14px;">
            <h2 class="section-heading">Subnets
              <button type="button" class="secondary help-btn" onclick="openSectionHelp('subnets')" title="About Subnets" aria-label="About Subnets">?</button>
            </h2>
            <table><tbody id="subnetTable"></tbody></table>
          </div>
        </div>

        <div class="panel">
          <h2 class="section-heading">OpenVPN Management Connection
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('mgmt_connection')" title="About OpenVPN Management Connection" aria-label="About OpenVPN Management Connection">?</button>
          </h2>
          <div class="muted">Connect to the running OpenVPN management socket.</div>
          <div class="row">
            <label>Host <input id="mgmtHost" value="127.0.0.1" placeholder="127.0.0.1"></label>
            <label>Port <input id="mgmtPort" value="7505" placeholder="7505"></label>
          </div>
          <label>Management Password (optional) <input id="mgmtPassword" type="password" placeholder="Only needed if management password auth is enabled"></label>
          <div class="actions">
            <button type="button" id="mgmtConnectBtn" onclick="connectManagement()">Connect</button>
            <button type="button" id="mgmtDisconnectBtn" class="secondary" onclick="disconnectManagement()">Disconnect</button>
            <span id="mgmtConnectionState" class="muted">Disconnected</span>
          </div>
          <div id="mgmtConnectMessage" class="status-note muted">Not connected.</div>
        </div>

        <div id="mgmtConnectedArea" style="display:none;">
        <div class="panel">
          <h2 class="section-heading">Realtime Stream
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('realtime_stream')" title="About Realtime Stream" aria-label="About Realtime Stream">?</button>
          </h2>
          <div class="row">
            <label><input type="checkbox" id="mgmtStateOn" checked> Enable state on</label>
            <label><input type="checkbox" id="mgmtLogOn" checked> Enable log on</label>
          </div>
          <div class="row">
            <label>Bytecount seconds (0 to disable) <input id="mgmtBytecountInterval" value="5"></label>
            <div class="actions"><button type="button" onclick="configureRealtimeStream()">Apply Stream Settings</button></div>
          </div>
          <pre id="mgmtEvents">No realtime management events yet.</pre>
        </div>

        <div class="panel">
          <h2 class="section-heading">Clients (status 3)
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('mgmt_clients')" title="About Clients status 3" aria-label="About Clients status 3">?</button>
          </h2>
          <div class="stat-cards">
            <div class="stat-card"><div class="label">Connected Clients</div><div class="value" id="mgmtClientCount">0</div></div>
            <div class="stat-card"><div class="label">Total RX</div><div class="value" id="mgmtTotalRx">0 B</div></div>
            <div class="stat-card"><div class="label">Total TX</div><div class="value" id="mgmtTotalTx">0 B</div></div>
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick="refreshManagementClients()">Refresh Clients</button>
          </div>
          <table>
            <thead>
              <tr><th>Common Name</th><th>Real Address</th><th>Virtual Address</th><th>RX</th><th>TX</th><th>Action</th></tr>
            </thead>
            <tbody id="mgmtClientTable"><tr><td class="muted" colspan="6">Not loaded.</td></tr></tbody>
          </table>
        </div>

        <div class="panel">
          <h2 class="section-heading">Management Command
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('mgmt_command')" title="About Management Command" aria-label="About Management Command">?</button>
          </h2>
          <div class="row">
            <label>Command <input id="mgmtCommand" placeholder="status 3"></label>
            <div class="actions">
              <button type="button" onclick="runManagementCommand()">Run Command</button>
            </div>
          </div>
          <div class="actions">
            <button type="button" class="secondary" onclick="runManagementCommand('version')">Version</button>
            <button type="button" class="secondary" onclick="runManagementCommand('status 3')">Status 3</button>
            <button type="button" class="secondary" onclick="runManagementCommand('state')">State</button>
            <button type="button" class="secondary" onclick="runManagementCommand('log 50')">Log 50</button>
          </div>
          <pre id="mgmtOutput">No management command run yet.</pre>
        </div>
        </div>
        </div>
      </section>

  <div id="initOverlay" class="overlay" aria-hidden="true">
    <div class="dialog init-dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:6px;">
        <h2 style="margin:0;">Initialize Server</h2>
        <button type="button" class="secondary" onclick="closeInitializeModal()">Close</button>
      </div>
        <div class="panel">
          <h2 class="section-heading">Certificate Details
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('cert_details')" title="About Certificate Details" aria-label="About Certificate Details">?</button>
          </h2>
          <div class="row">
            <label>Country <input id="certC" maxlength="2" oninput="checkInitializeReady()"></label>
            <label>State <input id="certST" oninput="checkInitializeReady()"></label>
          </div>
          <div class="row">
            <label>City <input id="certL" oninput="checkInitializeReady()"></label>
            <label>Organization <input id="certO" oninput="checkInitializeReady()"></label>
          </div>
          <div class="row">
            <label>Organizational Unit <input id="certOU" oninput="checkInitializeReady()"></label>
            <label>Email <input id="certEmail" type="email" oninput="checkInitializeReady()"></label>
          </div>
        </div>
        <div class="panel">
          <h2 class="section-heading">OpenVPN Server
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('openvpn_server')" title="About OpenVPN Server" aria-label="About OpenVPN Server">?</button>
          </h2>
          <div class="row">
            <label>Server Address <input id="serverAddress" placeholder="vpn.example.com" class="input-error" oninput="validateServerAddress(); checkInitializeReady()"></label>
            <label>Port <input id="serverPort" value="1194" oninput="validatePort(); checkInitializeReady()"></label>
          </div>
          <div id="serverAddressError" style="margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;">Server address is required.</div>
          <div class="row">
            <label>Protocol
              <select id="serverProto"><option value="udp">udp</option><option value="tcp">tcp</option></select>
            </label>
            <label>VPN Tunnel Subnet <input id="tunnelSubnet" value="10.8.0.0/24" oninput="validateSubnets(); checkInitializeReady()"></label>
          </div>
          <div id="tunnelSubnetError" style="margin-top:4px;margin-bottom:4px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;display:none;"></div>
          <label>Server LAN Subnet <input id="lanSubnet" value="192.168.1.0/24" oninput="validateSubnets()"></label>
          <div id="subnetErrorServer" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;"></div>
          <div style="margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:8px;">
            <div class="mtu-toggle-row">
              <label class="mtu-toggle-label">
                <input id="enableMtuFix" type="checkbox" onchange="toggleMtuFixFields(); validateMtuSettings(); checkInitializeReady()">
                Enable MTU/MSS compatibility mode
              </label>
            </div>
            <div id="mtuPresetRow" class="row" style="margin-top:8px;display:none;">
              <label>Preset
                <select id="mtuPreset" onchange="applyMtuPreset(this.value); validateMtuSettings(); checkInitializeReady()">
                  <option value="default">Default (1360 / 1428)</option>
                  <option value="lte">LTE/Cellular (1320 / 1400)</option>
                  <option value="pppoe">PPPoE (1360 / 1412)</option>
                  <option value="conservative">Conservative (1240 / 1300)</option>
                  <option value="manual">Manual</option>
                </select>
              </label>
            </div>
            <div id="mtuFixFields" class="row" style="margin-top:8px;display:none;">
              <label>mssfix <input id="mssfixValue" value="1360" inputmode="numeric" pattern="[0-9]*" oninput="setMtuPresetManual(); validateMtuSettings(); checkInitializeReady()"></label>
              <label>tun-mtu <input id="tunMtuValue" value="1428" inputmode="numeric" pattern="[0-9]*" oninput="setMtuPresetManual(); validateMtuSettings(); checkInitializeReady()"></label>
            </div>
            <div id="mtuErrorServer" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;"></div>
          </div>
          <h3>Data Ciphers</h3>
          <div class="checkboxes" id="cipherChecks"></div>
          <div id="cipherError" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;">At least one data cipher must be selected.</div>
        </div>
        <div class="panel">
          <h2 class="section-heading">Initial Clients
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('initial_clients')" title="About Initial Clients" aria-label="About Initial Clients">?</button>
          </h2>
          <div id="initClients"></div>
          <div id="nameErrorInitClients" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;"></div>
          <div id="subnetErrorClients" style="display:none;margin-top:8px;padding:8px 12px;border-radius:6px;background:#fdecea;color:#a73535;font-weight:600;"></div>
          <div class="actions">
            <button class="secondary" onclick="addClientRow('initClients')">Add Client</button>
            <button class="secondary" type="button" onclick="closeInitializeModal()">Cancel</button>
          </div>
        </div>
        <div class="panel">
          <h2 class="section-heading">Initialize
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('initialize')" title="About Initialize" aria-label="About Initialize">?</button>
          </h2>
          <div class="actions">
            <button onclick="initializeServer()" id="initializeBtn">Initialize Server</button>
          </div>
        </div>
        <div class="panel">
          <h2 class="section-heading">Initialization Progress
            <button type="button" class="secondary help-btn" onclick="openSectionHelp('init_progress')" title="About Initialization Progress" aria-label="About Initialization Progress">?</button>
          </h2>
          <div id="initProgressLabel" class="muted">No initialization running.</div>
          <div class="progress-wrap"><div id="initProgressBar" class="progress-bar"></div></div>
          <pre id="initProgressOutput">No output yet.</pre>
          <div class="actions" style="margin-top:10px;">
            <button id="initDoneCloseBtn" type="button" class="secondary" style="display:none;" onclick="closeInitializeModal()">Close</button>
          </div>
        </div>
    </div>
  </div>
    </div>
  </main>

  <div id="reinitOverlay" class="overlay" aria-hidden="true">
    <div class="dialog">
      <h2>Warning: Re-Initialize Server</h2>
      <p>This action starts from scratch.</p>
      <p>All previously generated server, CA, client certificates/configs, and package files will become unusable.</p>
      <div class="actions">
        <button class="danger" type="button" onclick="confirmReinitializeAccess()">I Understand, Continue</button>
        <button class="secondary" type="button" onclick="closeReinitializeWarning()">Cancel</button>
      </div>
    </div>
  </div>

  <div id="windowsGuideOverlay" class="overlay" aria-hidden="true">
    <div class="dialog guide-dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h2 id="windowsGuideTitle" style="margin:0;">Windows Deployment Guide</h2>
        <button type="button" class="secondary" onclick="closeWindowsGuideModal()">Close</button>
      </div>
      <div id="windowsGuideContent" class="guide-content muted">Loading guide...</div>
    </div>
  </div>

  <div id="ewonGuideOverlay" class="overlay" aria-hidden="true">
    <div class="dialog guide-dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h2 id="ewonGuideTitle" style="margin:0;">Deploy Client Package to Cosy+/Flexy</h2>
        <button type="button" class="secondary" onclick="closeEwonGuideModal()">Close</button>
      </div>
      <div id="ewonGuideContent" class="guide-content muted">Loading guide...</div>
    </div>
  </div>

  <div id="linuxGuideOverlay" class="overlay" aria-hidden="true">
    <div class="dialog guide-dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h2 id="linuxGuideTitle" style="margin:0;">Deploy Server Package to Linux</h2>
        <button type="button" class="secondary" onclick="closeLinuxGuideModal()">Close</button>
      </div>
      <div id="linuxGuideContent" class="guide-content muted">Loading guide...</div>
    </div>
  </div>

  <div id="flexedgeGuideOverlay" class="overlay" aria-hidden="true">
    <div class="dialog guide-dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h2 id="flexedgeGuideTitle" style="margin:0;">Deploy Server Package to FlexEdge</h2>
        <button type="button" class="secondary" onclick="closeFlexedgeGuideModal()">Close</button>
      </div>
      <div id="flexedgeGuideContent" class="guide-content muted">Loading guide...</div>
    </div>
  </div>

  <div id="anybusDefenderGuideOverlay" class="overlay" aria-hidden="true">
    <div class="dialog guide-dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h2 id="anybusDefenderGuideTitle" style="margin:0;">Deploy Server Setup to Anybus Defender</h2>
        <button type="button" class="secondary" onclick="closeAnybusDefenderGuideModal()">Close</button>
      </div>
      <div id="anybusDefenderGuideContent" class="guide-content muted">Loading guide...</div>
    </div>
  </div>

  <div id="sectionHelpOverlay" class="overlay" aria-hidden="true">
    <div class="dialog">
      <div class="actions" style="justify-content:space-between;align-items:center;margin-bottom:8px;">
        <h2 id="sectionHelpTitle" style="margin:0;">Section Help</h2>
        <button type="button" class="secondary" onclick="closeSectionHelp()">Close</button>
      </div>
      <div id="sectionHelpContent" class="section-help-content muted">No help text is available for this section yet.</div>
    </div>
  </div>

  <script>
    let state = {};
    let activeJob = null;
    let activeJobPath = "";
    let activePackageTarget = "";
    let mgmtEventCursor = 0;
    let mgmtConnected = false;
    let reinitializeUnlocked = false;
    let windowsGuideLoaded = false;
    let ewonGuideLoaded = false;
    let linuxGuideLoaded = false;
    let flexedgeGuideLoaded = false;
    let anybusDefenderGuideLoaded = false;

    const SECTION_HELP = {
      server: {
        title: "Server",
        html: `<p>Use this section to initialize or re-initialize your OpenVPN server and review current server settings.</p><p>After initialization, this area also gives deployment package buttons for Windows, Linux, FlexEdge, and Anybus Defender targets.</p>`,
      },
      add_client: {
        title: "Add Client",
        html: `<p>Generate additional client certificates and configuration packages after the server is initialized.</p><p>Each client name must be unique. Optional routed subnet values are validated to prevent overlap with existing networks.</p>`,
      },
      clients: {
        title: "Clients",
        html: `<p>This table lists all known clients and the packages available for each client.</p><p>Use the action buttons to deploy a client package or revoke a client certificate when access should be removed.</p>`,
      },
      subnets: {
        title: "Subnets",
        html: `<p>This section shows all named subnets currently tracked by the toolkit.</p><p>Subnet data is used for route generation and overlap checks during initialization and client creation.</p>`,
      },
      mgmt_connection: {
        title: "OpenVPN Management Connection",
        html: `<p>Connect the Web UI to a running OpenVPN management socket for live status, logs, and commands.</p><p>Host is usually 127.0.0.1 and port is usually 7505 unless your server is configured differently.</p>`,
      },
      realtime_stream: {
        title: "Realtime Stream",
        html: `<p>Controls OpenVPN management stream settings such as state events, log events, and bytecount interval.</p><p>Use this to tune how much realtime data is shown in the event output area.</p>`,
      },
      mgmt_clients: {
        title: "Clients (status 3)",
        html: `<p>Displays connected client sessions from the OpenVPN management interface and traffic totals.</p><p>You can refresh the view and disconnect specific active sessions from this table.</p>`,
      },
      mgmt_command: {
        title: "Management Command",
        html: `<p>Run raw OpenVPN management commands and inspect the command output.</p><p>Quick buttons are provided for common commands such as version, state, and status 3.</p>`,
      },
      cert_details: {
        title: "Certificate Details",
        html: `<p>These values are written into CA and certificate metadata during server initialization.</p><p>Set organization details carefully before first deployment to keep certificate identity consistent.</p>`,
      },
      openvpn_server: {
        title: "OpenVPN Server",
        html: `<p>Configure server address, port, protocol, VPN tunnel subnet, and optional LAN subnet for routing.</p><p>At least one data cipher is required, and subnet entries are validated before initialization starts.</p><p>Advanced MTU/MSS settings are optional and can be enabled for links that need smaller packet sizes.</p>`,
      },
      initial_clients: {
        title: "Initial Clients",
        html: `<p>Define the client certificates that should be created during first server initialization.</p><p>You can add more clients later from the Add Client section after the server is already initialized.</p>`,
      },
      initialize: {
        title: "Initialize",
        html: `<p>Starts the full setup process: CA creation, server certificates, server configuration, and initial client package generation.</p><p>Re-initializing replaces existing certificate state, so previously issued packages become unusable.</p>`,
      },
      init_progress: {
        title: "Initialization Progress",
        html: `<p>Shows live output from the initialization job, including long-running crypto steps.</p><p>If this panel reports errors, correct inputs and run initialization again.</p>`,
      },
    };

    function openSectionHelp(key) {
      const item = SECTION_HELP[key];
      if (!item) return;
      sectionHelpTitle.textContent = item.title;
      sectionHelpContent.className = "section-help-content";
      sectionHelpContent.innerHTML = item.html;
      sectionHelpOverlay.classList.add("show");
      sectionHelpOverlay.setAttribute("aria-hidden", "false");
    }

    function closeSectionHelp() {
      sectionHelpOverlay.classList.remove("show");
      sectionHelpOverlay.setAttribute("aria-hidden", "true");
    }

    function setClientActionMessage(text = "", kind = "muted") {
      if (!text) {
        clientActionMessage.style.display = "none";
        clientActionMessage.textContent = "";
        clientActionMessage.className = "status-note muted";
        return;
      }
      clientActionMessage.style.display = "block";
      clientActionMessage.textContent = text;
      clientActionMessage.className = `status-note ${kind}`;
    }

    function fmtBytes(n) {
      const num = Number(n) || 0;
      if (num < 1024) return `${num} B`;
      if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
      if (num < 1024 * 1024 * 1024) return `${(num / (1024 * 1024)).toFixed(1)} MB`;
      return `${(num / (1024 * 1024 * 1024)).toFixed(2)} GB`;
    }

    function normalizeJobText(text) {
      // OpenSSL spinner output often emits carriage returns; normalize for readable logs.
      return String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    }

    function setMgmtMessage(text, kind = "muted") {
      mgmtConnectMessage.textContent = text;
      mgmtConnectMessage.className = `status-note ${kind}`;
    }

    function setCrlNotice(text = "") {
      if (!text) {
        crlNotice.style.display = "none";
        crlNotice.textContent = "";
        return;
      }
      crlNotice.style.display = "block";
      crlNotice.textContent = text;
    }

    function applyTheme(theme) {
      const dark = theme === "dark";
      document.body.classList.toggle("dark-theme", dark);
      themeToggle.textContent = dark ? "Light Mode" : "Dark Mode";
      try { localStorage.setItem("ez_theme", theme); } catch (_) {}
    }

    function toggleTheme() {
      const dark = document.body.classList.contains("dark-theme");
      applyTheme(dark ? "light" : "dark");
    }

    function initTheme() {
      let saved = "light";
      try { saved = localStorage.getItem("ez_theme") || "light"; } catch (_) {}
      applyTheme(saved === "dark" ? "dark" : "light");
    }

    function exitApp() {
      if (!confirm("Exit EZ OpenVPN Toolkit now? Any running operations will stop.")) {
        return;
      }

      exitAppBtn.disabled = true;
      exitAppBtn.textContent = "Shutting down...";

      api("/api/app/exit", { reason: "user_requested" })
        .then(() => {
          readyText.textContent = "Shutting down";
          setTimeout(() => {
            try { window.close(); } catch (_) {}
          }, 350);
        })
        .catch(err => {
          const msg = String(err.message || err || "");
          if (msg.toLowerCase().includes("failed to fetch")) {
            // Expected when shutdown drops the socket before fetch resolves.
            readyText.textContent = "Shutting down";
            setTimeout(() => {
              try { window.close(); } catch (_) {}
            }, 350);
            return;
          }
          exitAppBtn.disabled = false;
          exitAppBtn.textContent = "Exit App";
          alert(`Could not shut down app: ${msg}`);
        });
    }

    function openInitializeModal() {
      initOverlay.classList.add("show");
      initOverlay.setAttribute("aria-hidden", "false");
      initDoneCloseBtn.style.display = "none";
      toggleMtuFixFields();
      validateMtuSettings();
      validateSubnets();
      checkInitializeReady();
    }

    function closeInitializeModal() {
      initOverlay.classList.remove("show");
      initOverlay.setAttribute("aria-hidden", "true");
    }

    function openReinitializeWarning() {
      reinitOverlay.classList.add("show");
      reinitOverlay.setAttribute("aria-hidden", "false");
    }

    function closeReinitializeWarning() {
      reinitOverlay.classList.remove("show");
      reinitOverlay.setAttribute("aria-hidden", "true");
    }

    function openWindowsGuideModal() {
      windowsGuideOverlay.classList.add("show");
      windowsGuideOverlay.setAttribute("aria-hidden", "false");
      if (!windowsGuideLoaded) {
        windowsGuideContent.className = "guide-content muted";
        windowsGuideContent.textContent = "Loading guide...";
        api("/api/windows-guide").then(data => {
          windowsGuideTitle.textContent = data.title || "Windows Deployment Guide";
          windowsGuideContent.className = "guide-content";
          windowsGuideContent.innerHTML = data.html || "<p>No guide content found.</p>";
          windowsGuideLoaded = true;
        }).catch(err => {
          windowsGuideContent.className = "guide-content";
          windowsGuideContent.innerHTML = `<p>Failed to load guide: ${String(err.message || err)}</p>`;
        });
      }
    }

    function closeWindowsGuideModal() {
      windowsGuideOverlay.classList.remove("show");
      windowsGuideOverlay.setAttribute("aria-hidden", "true");
    }

    function openEwonGuideModal() {
      ewonGuideOverlay.classList.add("show");
      ewonGuideOverlay.setAttribute("aria-hidden", "false");
      if (!ewonGuideLoaded) {
        ewonGuideContent.className = "guide-content muted";
        ewonGuideContent.textContent = "Loading guide...";
        api("/api/ewon-guide").then(data => {
          ewonGuideTitle.textContent = data.title || "Deploy Client Package to Cosy+/Flexy";
          ewonGuideContent.className = "guide-content";
          ewonGuideContent.innerHTML = data.html || "<p>No guide content found.</p>";
          ewonGuideLoaded = true;
        }).catch(err => {
          ewonGuideContent.className = "guide-content";
          ewonGuideContent.innerHTML = `<p>Failed to load guide: ${String(err.message || err)}</p>`;
        });
      }
    }

    function closeEwonGuideModal() {
      ewonGuideOverlay.classList.remove("show");
      ewonGuideOverlay.setAttribute("aria-hidden", "true");
    }

    function openLinuxGuideModal() {
      linuxGuideOverlay.classList.add("show");
      linuxGuideOverlay.setAttribute("aria-hidden", "false");
      if (!linuxGuideLoaded) {
        linuxGuideContent.className = "guide-content muted";
        linuxGuideContent.textContent = "Loading guide...";
        api("/api/linux-guide").then(data => {
          linuxGuideTitle.textContent = data.title || "Deploy Server Package to Linux";
          linuxGuideContent.className = "guide-content";
          linuxGuideContent.innerHTML = data.html || "<p>No guide content found.</p>";
          linuxGuideLoaded = true;
        }).catch(err => {
          linuxGuideContent.className = "guide-content";
          linuxGuideContent.innerHTML = `<p>Failed to load guide: ${String(err.message || err)}</p>`;
        });
      }
    }

    function closeLinuxGuideModal() {
      linuxGuideOverlay.classList.remove("show");
      linuxGuideOverlay.setAttribute("aria-hidden", "true");
    }

    function openFlexedgeGuideModal() {
      flexedgeGuideOverlay.classList.add("show");
      flexedgeGuideOverlay.setAttribute("aria-hidden", "false");
      if (!flexedgeGuideLoaded) {
        flexedgeGuideContent.className = "guide-content muted";
        flexedgeGuideContent.textContent = "Loading guide...";
        api("/api/flexedge-guide").then(data => {
          flexedgeGuideTitle.textContent = data.title || "Deploy Server Package to FlexEdge";
          flexedgeGuideContent.className = "guide-content";
          flexedgeGuideContent.innerHTML = data.html || "<p>No guide content found.</p>";
          flexedgeGuideLoaded = true;
        }).catch(err => {
          flexedgeGuideContent.className = "guide-content";
          flexedgeGuideContent.innerHTML = `<p>Failed to load guide: ${String(err.message || err)}</p>`;
        });
      }
    }

    function closeFlexedgeGuideModal() {
      flexedgeGuideOverlay.classList.remove("show");
      flexedgeGuideOverlay.setAttribute("aria-hidden", "true");
    }

    function openAnybusDefenderGuideModal() {
      anybusDefenderGuideOverlay.classList.add("show");
      anybusDefenderGuideOverlay.setAttribute("aria-hidden", "false");
      if (!anybusDefenderGuideLoaded) {
        anybusDefenderGuideContent.className = "guide-content muted";
        anybusDefenderGuideContent.textContent = "Loading guide...";
        api("/api/anybus-defender-guide").then(data => {
          anybusDefenderGuideTitle.textContent = data.title || "Deploy Server Setup to Anybus Defender";
          anybusDefenderGuideContent.className = "guide-content";
          anybusDefenderGuideContent.innerHTML = data.html || "<p>No guide content found.</p>";
          anybusDefenderGuideLoaded = true;
        }).catch(err => {
          anybusDefenderGuideContent.className = "guide-content";
          anybusDefenderGuideContent.innerHTML = `<p>Failed to load guide: ${String(err.message || err)}</p>`;
        });
      }
    }

    function closeAnybusDefenderGuideModal() {
      anybusDefenderGuideOverlay.classList.remove("show");
      anybusDefenderGuideOverlay.setAttribute("aria-hidden", "true");
    }

    function confirmReinitializeAccess() {
      reinitializeUnlocked = true;
      closeReinitializeWarning();
      openInitializeModal();
      initializeBtn.disabled = false;
    }

    const CSRF_TOKEN = "__CSRF_TOKEN__";
    const CLIENT_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
    const RESERVED_CLIENT_NAMES = new Set(["server", "ca", "openvpn", "root", "admin"]);
    const PACKAGE_BUTTON_SPECS = [
      {
        id: "packageWindowsBtn",
        target: "windows",
        filename: "OpenVPN_Server_Windows.zip",
        generateLabel: "Generate Windows Deployment Package",
      },
      {
        id: "packageLinuxBtn",
        target: "linux",
        filename: "OpenVPN_Server_Linux.zip",
        generateLabel: "Generate Linux Deployment Package",
      },
      {
        id: "packageFlexedgeBtn",
        target: "flexedge",
        filename: "OpenVPN_Server_FlexEdge.zip",
        generateLabel: "Generate FlexEdge Deployment Package",
      },
      {
        id: "packageAnybusDefenderBtn",
        target: "anybus_defender",
        filename: "OpenVPN_Server_Anybus_Defender.zip",
        generateLabel: "Generate Anybus Defender Deployment Package",
      },
    ];

    const MTU_PRESETS = {
      default: { mssfix: 1360, tunMtu: 1428 },
      lte: { mssfix: 1320, tunMtu: 1400 },
      pppoe: { mssfix: 1360, tunMtu: 1412 },
      conservative: { mssfix: 1240, tunMtu: 1300 },
    };

    // --- Subnet overlap validation (mirrors subnet_management.py logic) ---
    function parseIPv4(addrStr) {
      const parts = addrStr.trim().split(".").map(Number);
      if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
      return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
    }

    function netmaskToPrefixLen(maskInt) {
      // Count leading 1-bits; reject non-contiguous masks
      const bits = maskInt.toString(2).padStart(32, "0");
      const firstZero = bits.indexOf("0");
      if (firstZero === -1) return 32;
      if (bits.indexOf("1", firstZero) !== -1) return null; // non-contiguous
      return firstZero;
    }

    function parseCidr(input) {
      input = (input || "").trim();
      if (!input) return null;
      try {
        let addrStr, prefix;
        if (input.includes("/")) {
          // CIDR notation: 10.0.0.0/24
          [addrStr, prefix] = input.split("/");
          prefix = parseInt(prefix, 10);
          if (isNaN(prefix) || prefix < 0 || prefix > 32) return null;
        } else if (input.includes(" ")) {
          // Dotted decimal: 10.0.0.0 255.255.255.0
          const [a, m] = input.split(/\s+/);
          addrStr = a;
          const maskInt = parseIPv4(m);
          if (maskInt === null) return null;
          prefix = netmaskToPrefixLen(maskInt);
          if (prefix === null) return null;
        } else {
          // Bare host address — treat as /32
          addrStr = input;
          prefix = 32;
        }
        const addr = parseIPv4(addrStr);
        if (addr === null) return null;
        const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
        const network = (addr & mask) >>> 0;
        return { network, mask, prefix };
      } catch { return null; }
    }

    function subnetsOverlap(a, b) {
      if (!a || !b) return false;
      return (a.network >>> 0) === ((b.network & a.mask) >>> 0) ||
             (b.network >>> 0) === ((a.network & b.mask) >>> 0);
    }

    function validateSubnets() {
      const allSubnetInputs = [
        tunnelSubnet,
        lanSubnet,
        ...document.querySelectorAll("#initClients .client-subnet"),
      ];
      allSubnetInputs.forEach(el => el.classList.remove("input-error"));

      const tunnelBox = document.getElementById("tunnelSubnetError");
      const tunnelVal = tunnelSubnet.value.trim();
      if (!tunnelVal) {
        tunnelSubnet.classList.add("input-error");
        tunnelBox.style.display = "block";
        tunnelBox.textContent = "VPN Tunnel Subnet is required.";
      } else if (!parseCidr(tunnelVal)) {
        tunnelSubnet.classList.add("input-error");
        tunnelBox.style.display = "block";
        tunnelBox.textContent = "VPN Tunnel Subnet: invalid CIDR notation.";
      } else {
        tunnelBox.style.display = "none";
        tunnelBox.textContent = "";
      }

      const inputs = [
        ...(tunnelVal && parseCidr(tunnelVal) ? [{ label: "VPN Tunnel Subnet", value: tunnelVal, area: "server", el: tunnelSubnet }] : []),
        ...(lanSubnet.value.trim() ? [{ label: "Server LAN Subnet", value: lanSubnet.value.trim(), area: "server", el: lanSubnet }] : []),
        ...[...document.querySelectorAll("#initClients .client-subnet")]
            .map((el, i) => {
              const row = el.closest(".client-row");
              const nameEl = row ? row.querySelector(".client-name") : null;
              const name = nameEl ? nameEl.value.trim() : "";
              const labelBase = name || `Client ${i + 1}`;
              return { label: `${labelBase} subnet`, value: el.value.trim(), area: "clients", el };
            })
            .filter(s => s.value)
      ];
      const parsed = inputs.map(s => ({ ...s, net: parseCidr(s.value) }));
      const serverErrors = [];
      const clientErrors = [];
      const highlighted = new Set();
      const invalidEntries = parsed.filter(s => s.value && !s.net);
      invalidEntries.forEach(s => {
        const msg = `"${s.label}": invalid CIDR notation.`;
        highlighted.add(s.el);
        if (s.area === "server") {
          serverErrors.push(msg);
        } else {
          clientErrors.push(msg);
        }
      });
      const valid = parsed.filter(s => s.net);
      for (let i = 0; i < valid.length; i++) {
        for (let j = i + 1; j < valid.length; j++) {
          if (subnetsOverlap(valid[i].net, valid[j].net)) {
            const msg = `"${valid[i].label}" (${valid[i].value}) overlaps with "${valid[j].label}" (${valid[j].value}).`;
            highlighted.add(valid[i].el);
            highlighted.add(valid[j].el);
            const areas = new Set([valid[i].area, valid[j].area]);
            if (areas.has("server")) {
              serverErrors.push(msg);
            }
            if (areas.has("clients")) {
              clientErrors.push(msg);
            }
          }
        }
      }

      highlighted.forEach(el => el.classList.add("input-error"));

      const serverBox = document.getElementById("subnetErrorServer");
      if (serverErrors.length) {
        serverBox.style.display = "block";
        serverBox.innerHTML = "Subnet conflict:<br>" + serverErrors.map(e => `&bull; ${e}`).join("<br>");
      } else {
        serverBox.style.display = "none";
        serverBox.textContent = "";
      }

      const clientBox = document.getElementById("subnetErrorClients");
      if (clientErrors.length) {
        clientBox.style.display = "block";
        clientBox.innerHTML = "Subnet conflict:<br>" + clientErrors.map(e => `&bull; ${e}`).join("<br>");
      } else {
        clientBox.style.display = "none";
        clientBox.textContent = "";
      }

      return (serverErrors.length + clientErrors.length) === 0 && !!tunnelVal && !!parseCidr(tunnelVal);
    }
    // --- End subnet validation ---

    function api(path, body) {
      return fetch(path, {
        method: body ? "POST" : "GET",
        headers: body ? {"Content-Type": "application/json", "X-CSRF-Token": CSRF_TOKEN} : {},
        body: body ? JSON.stringify(body) : undefined
      }).then(async res => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || res.statusText);
        return data;
      });
    }

    function addClientRow(target, name = "", subnet = "", allowRemove = true) {
      const formId = target === "addClients" ? "addClientsForm" : target;
      const wrap = document.getElementById(formId);
      const row = document.createElement("div");
      row.className = "client-row";
      row.innerHTML = `
        <label>Name <input class="client-name" value="${name}" placeholder="client-name"></label>
        <label>Routed subnet <input class="client-subnet" value="${subnet}" placeholder="optional, e.g. 10.255.254.0/24"></label>
        ${allowRemove ? '<button type="button" class="secondary">Remove</button>' : '<span></span>'}`;
      const removeBtn = row.querySelector("button");
      if (removeBtn) {
        removeBtn.onclick = () => {
          row.remove();
          validateSubnets();
          validateInitClientNames();
          validateAddClientNames();
          validateAddClientSubnets();
        };
      }
      row.querySelector(".client-name").addEventListener("input", () => {
        if (target === "initClients") validateInitClientNames();
        if (target === "addClients") validateAddClientNames();
      });
      row.querySelector(".client-subnet").addEventListener("input", () => {
        validateSubnets();
        validateAddClientSubnets();
      });
      wrap.appendChild(row);
      if (target === "initClients") {
        validateSubnets();
        validateInitClientNames();
      }
      if (target === "addClients") {
        validateAddClientNames();
        validateAddClientSubnets();
      }
    }

    function resetAddClientsForm() {
      document.getElementById("addClientsForm").innerHTML = "";
      addClientRow("addClients", "", "", false);
    }

    function collectClients(target) {
      const formId = target === "addClients" ? "addClientsForm" : target;
      return [...document.querySelectorAll(`#${formId} .client-row`)].map(row => ({
        name: row.querySelector(".client-name").value.trim(),
        subnet: row.querySelector(".client-subnet").value.trim()
      })).filter(item => item.name);
    }

    function validateInitClientNames() {
      const box = document.getElementById("nameErrorInitClients");
      const nameInputs = [...document.querySelectorAll("#initClients .client-name")];
      nameInputs.forEach(el => el.classList.remove("input-error"));

      const errors = [];
      const enteredByLower = new Map();

      for (let i = 0; i < nameInputs.length; i++) {
        const el = nameInputs[i];
        const name = (el.value || "").trim();
        if (!name) {
          continue;
        }

        const label = `Client ${i + 1} name`;
        if (!CLIENT_NAME_PATTERN.test(name)) {
          el.classList.add("input-error");
          errors.push(`"${label}": invalid name. Use 1-64 chars: letters, numbers, underscore, dash, dot.`);
          continue;
        }

        const lower = name.toLowerCase();
        if (RESERVED_CLIENT_NAMES.has(lower)) {
          el.classList.add("input-error");
          errors.push(`"${label}" (${name}) is reserved and cannot be used.`);
        }

        if (enteredByLower.has(lower)) {
          el.classList.add("input-error");
          const prev = enteredByLower.get(lower);
          if (prev && prev.el) {
            prev.el.classList.add("input-error");
          }
          errors.push(`"${label}" (${name}) duplicates another client name in this form.`);
        } else {
          enteredByLower.set(lower, { el, name });
        }
      }

      if (errors.length) {
        box.style.display = "block";
        box.innerHTML = "Client name validation:<br>" + errors.map(e => `&bull; ${e}`).join("<br>");
      } else {
        box.style.display = "none";
        box.textContent = "";
      }

      return errors.length === 0;
    }

    function validateAddClientNames() {
      const box = document.getElementById("nameErrorAddClients");
      const nameInputs = [...document.querySelectorAll("#addClientsForm .client-name")];
      nameInputs.forEach(el => el.classList.remove("input-error"));

      const errors = [];
      const existingByLower = new Map((state.clients || []).map(name => [String(name).toLowerCase(), String(name)]));
      const enteredByLower = new Map();

      for (let i = 0; i < nameInputs.length; i++) {
        const el = nameInputs[i];
        const name = (el.value || "").trim();
        if (!name) {
          continue;
        }

        const label = `Client ${i + 1} name`;
        if (!CLIENT_NAME_PATTERN.test(name)) {
          el.classList.add("input-error");
          errors.push(`"${label}": invalid name. Use 1-64 chars: letters, numbers, underscore, dash, dot.`);
          continue;
        }

        const lower = name.toLowerCase();
        if (RESERVED_CLIENT_NAMES.has(lower)) {
          el.classList.add("input-error");
          errors.push(`"${label}" (${name}) is reserved and cannot be used.`);
        }

        const existing = existingByLower.get(lower);
        if (existing) {
          el.classList.add("input-error");
          errors.push(`"${label}" (${name}) already exists as "${existing}".`);
        }

        if (enteredByLower.has(lower)) {
          el.classList.add("input-error");
          const prev = enteredByLower.get(lower);
          if (prev && prev.el) {
            prev.el.classList.add("input-error");
          }
          errors.push(`"${label}" (${name}) duplicates another client name in this form.`);
        } else {
          enteredByLower.set(lower, { el, name });
        }
      }

      if (errors.length) {
        box.style.display = "block";
        box.innerHTML = "Client name validation:<br>" + errors.map(e => `&bull; ${e}`).join("<br>");
      } else {
        box.style.display = "none";
        box.textContent = "";
      }

      return errors.length === 0;
    }

    function validateAddClientSubnets() {
      const box = document.getElementById("subnetErrorAddClients");
      const subnetInputs = [...document.querySelectorAll("#addClientsForm .client-subnet")];
      subnetInputs.forEach(el => el.classList.remove("input-error"));

      const entered = subnetInputs
        .map((el, i) => {
          const row = el.closest(".client-row");
          const nameEl = row ? row.querySelector(".client-name") : null;
          const name = nameEl ? nameEl.value.trim() : "";
          const labelBase = name || `Client ${i + 1}`;
          return { label: `${labelBase} subnet`, value: (el.value || "").trim(), el };
        })
        .filter(item => item.value);

      const parsedEntered = entered.map(item => ({ ...item, net: parseCidr(item.value) }));
      const errors = [];

      for (const item of parsedEntered) {
        if (!item.net) {
          item.el.classList.add("input-error");
          errors.push(`"${item.label}": invalid CIDR notation.`);
        }
      }

      const validEntered = parsedEntered.filter(item => item.net);
      const existing = (state.subnets || [])
        .map(row => ({
          label: row.Name || "Existing subnet",
          value: (row.Subnet || "").trim(),
          net: parseCidr((row.Subnet || "").trim()),
        }))
        .filter(item => item.net);

      for (const candidate of validEntered) {
        for (const current of existing) {
          if (subnetsOverlap(candidate.net, current.net)) {
            candidate.el.classList.add("input-error");
            errors.push(
              `"${candidate.label}" (${candidate.value}) overlaps with "${current.label}" (${current.value}).`
            );
          }
        }
      }

      for (let i = 0; i < validEntered.length; i++) {
        for (let j = i + 1; j < validEntered.length; j++) {
          if (subnetsOverlap(validEntered[i].net, validEntered[j].net)) {
            validEntered[i].el.classList.add("input-error");
            validEntered[j].el.classList.add("input-error");
            errors.push(
              `"${validEntered[i].label}" (${validEntered[i].value}) overlaps with "${validEntered[j].label}" (${validEntered[j].value}).`
            );
          }
        }
      }

      if (errors.length) {
        box.style.display = "block";
        box.innerHTML = "Subnet conflict:<br>" + errors.map(e => `&bull; ${e}`).join("<br>");
      } else {
        box.style.display = "none";
        box.textContent = "";
      }

      return errors.length === 0;
    }

    function selectedCiphers() {
      return [...document.querySelectorAll(".cipher:checked")].map(item => item.value);
    }

    function validatePort() {
      const el = document.getElementById("serverPort");
      const port = parseInt((el && el.value) || "", 10);
      if (!el) return;
      if (isNaN(port) || port < 1 || port > 65535) {
        el.classList.add("input-error");
      } else {
        el.classList.remove("input-error");
      }
    }

    function validatePort() {
      const el = document.getElementById("serverPort");
      if (!el) return;
      const port = parseInt(el.value || "", 10);
      if (isNaN(port) || port < 1 || port > 65535) {
        el.classList.add("input-error");
      } else {
        el.classList.remove("input-error");
      }
    }

    function validateServerAddress() {
      const el = document.getElementById("serverAddress");
      const box = document.getElementById("serverAddressError");
      const val = el.value.trim();
      if (!val) {
        el.classList.add("input-error");
        box.style.display = "block";
        box.textContent = "Server address is required.";
        return false;
      }
      // IPv4
      const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
      if (ipv4Re.test(val)) {
        const parts = val.split(".").map(Number);
        if (parts.every(p => p >= 0 && p <= 255)) {
          el.classList.remove("input-error");
          box.style.display = "none";
          return true;
        }
      }
      // IPv6 (simplified: colon-hex notation)
      if (val.includes(":") && /^[0-9a-fA-F:]+$/.test(val)) {
        el.classList.remove("input-error");
        box.style.display = "none";
        return true;
      }
      // Domain name
      const domainRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$/;
      if (domainRe.test(val) && val.length <= 253) {
        el.classList.remove("input-error");
        box.style.display = "none";
        return true;
      }
      el.classList.add("input-error");
      box.style.display = "block";
      box.textContent = "Enter a valid IPv4 address, IPv6 address, or domain name.";
      return false;
    }

    function isInitializeFormReady() {
      const addrEl = document.getElementById("serverAddress");
      const addrVal = addrEl ? addrEl.value.trim() : "";
      if (!addrVal) return false;
      // Re-use validateServerAddress result without side-effects by checking class
      if (addrEl && addrEl.classList.contains("input-error")) return false;
      const port = parseInt((serverPort && serverPort.value) || "", 10);
      if (isNaN(port) || port < 1 || port > 65535) return false;
      const tunnelVal = tunnelSubnet ? tunnelSubnet.value.trim() : "";
      if (!tunnelVal || !parseCidr(tunnelVal)) return false;
      if (selectedCiphers().length === 0) return false;
      if (!validateMtuSettings()) return false;
      const certEls = [certC, certST, certL, certO, certOU, certEmail];
      if (certEls.some(el => !el || el.value.trim() === "")) return false;
      return true;
    }

    function checkInitializeReady() {
      if (state.initialized && !reinitializeUnlocked) return;
      validatePort();
      validateCiphers();
      initializeBtn.disabled = !isInitializeFormReady();
    }

    function validateCiphers() {
      const box = document.getElementById("cipherError");
      if (!box) return;
      if (selectedCiphers().length === 0) {
        box.style.display = "block";
      } else {
        box.style.display = "none";
      }
    }

    function toggleMtuFixFields() {
      const enabled = document.getElementById("enableMtuFix")?.checked;
      const wrap = document.getElementById("mtuFixFields");
      const presetRow = document.getElementById("mtuPresetRow");
      if (!wrap) return;
      wrap.style.display = enabled ? "flex" : "none";
      if (presetRow) {
        presetRow.style.display = enabled ? "flex" : "none";
      }
    }

    function setMtuPresetManual() {
      const presetEl = document.getElementById("mtuPreset");
      if (presetEl) {
        presetEl.value = "manual";
      }
    }

    function applyMtuPreset(presetKey) {
      if (presetKey === "manual") return;
      const preset = MTU_PRESETS[presetKey];
      if (!preset) return;
      const mssEl = document.getElementById("mssfixValue");
      const tunEl = document.getElementById("tunMtuValue");
      if (mssEl) mssEl.value = String(preset.mssfix);
      if (tunEl) tunEl.value = String(preset.tunMtu);
    }

    function inferMtuPreset(mssfix, tunMtu) {
      const mss = Number(mssfix);
      const tun = Number(tunMtu);
      for (const [key, preset] of Object.entries(MTU_PRESETS)) {
        if (preset.mssfix === mss && preset.tunMtu === tun) {
          return key;
        }
      }
      return "manual";
    }

    function validateMtuSettings() {
      const enabledEl = document.getElementById("enableMtuFix");
      const mssEl = document.getElementById("mssfixValue");
      const tunEl = document.getElementById("tunMtuValue");
      const box = document.getElementById("mtuErrorServer");
      if (!enabledEl || !mssEl || !tunEl || !box) return true;

      mssEl.classList.remove("input-error");
      tunEl.classList.remove("input-error");

      if (!enabledEl.checked) {
        box.style.display = "none";
        box.textContent = "";
        return true;
      }

      const errors = [];
      const mssRaw = (mssEl.value || "").trim();
      const tunRaw = (tunEl.value || "").trim();

      if (!/^\d+$/.test(mssRaw)) {
        mssEl.classList.add("input-error");
        errors.push("mssfix must be a positive integer.");
      }
      if (!/^\d+$/.test(tunRaw)) {
        tunEl.classList.add("input-error");
        errors.push("tun-mtu must be a positive integer.");
      }

      if (/^\d+$/.test(mssRaw)) {
        const mss = parseInt(mssRaw, 10);
        if (mss < 900 || mss > 1460) {
          mssEl.classList.add("input-error");
          errors.push("mssfix must be between 900 and 1460.");
        }
      }

      if (/^\d+$/.test(tunRaw)) {
        const tun = parseInt(tunRaw, 10);
        if (tun < 1200 || tun > 2000) {
          tunEl.classList.add("input-error");
          errors.push("tun-mtu must be between 1200 and 2000.");
        }
      }

      if (errors.length) {
        box.style.display = "block";
        box.innerHTML = "MTU/MSS validation:<br>" + errors.map(e => `&bull; ${e}`).join("<br>");
        return false;
      }

      box.style.display = "none";
      box.textContent = "";
      return true;
    }

    function initializeServer() {
      if (state.initialized && !reinitializeUnlocked) {
        openReinitializeWarning();
        return;
      }
      if (!validateInitClientNames()) {
        initProgressLabel.textContent = "Initialize server: fix initial client name validation errors first.";
        initProgressBar.className = "progress-bar failed";
        return;
      }
      if (!validateMtuSettings()) return;
      if (!validateSubnets()) return;
      const mtuFixEnabled = document.getElementById("enableMtuFix")?.checked || false;
      const mssfix = (document.getElementById("mssfixValue")?.value || "").trim();
      const tunMtu = (document.getElementById("tunMtuValue")?.value || "").trim();
      const payload = {
        certificate_details: {
          C: certC.value, ST: certST.value, L: certL.value, O: certO.value,
          OU: certOU.value, email_address: certEmail.value
        },
        server_address: serverAddress.value,
        port: serverPort.value,
        proto: serverProto.value,
        openvpn_tunnel_subnet: tunnelSubnet.value,
        server_lan_subnet: lanSubnet.value,
        data_ciphers: selectedCiphers(),
        mtu_fix_enabled: mtuFixEnabled,
        mssfix: mtuFixEnabled ? mssfix : null,
        tun_mtu: mtuFixEnabled ? tunMtu : null,
        clients: collectClients("initClients")
      };
      const initPath = state.initialized ? "/api/reinitialize" : "/api/initialize";
      runJob(initPath, payload);
    }

    function addClients() {
      if (activeJobPath) {
        setClientActionMessage("Please wait for the current operation to finish.", "muted");
        return;
      }
      const clients = collectClients("addClients");
      if (!clients.length) {
        setClientActionMessage("Enter a client name first.", "err");
        return;
      }
      if (!validateAddClientNames()) {
        setClientActionMessage("Fix client name validation errors first.", "err");
        return;
      }
      if (!validateAddClientSubnets()) {
        setClientActionMessage("Fix subnet validation errors first.", "err");
        return;
      }
      if (clients.length > 1) {
        setClientActionMessage("One client at a time on this page.", "err");
        return;
      }
      runJob("/api/clients", {clients});
    }

    function setAddClientBusy(busy) {
      const btn = document.getElementById("generateClientBtn");
      if (!btn) return;
      btn.disabled = !!busy;
      btn.textContent = busy ? "Generating..." : "Generate Client";
    }

    function revokeClientByName(name) {
      const clientName = (name || "").trim();
      if (!clientName) return;
      if (!confirm(`Revoke client '${clientName}'? This updates the CRL and requires redeploying updated server packages.`)) {
        return;
      }
      runJob("/api/revoke", {client_name: clientName});
    }

    function packageClientEwonByName(name) {
      const clientName = (name || "").trim();
      if (!clientName) return;
      runJob("/api/package-client-ewon", {client_name: clientName});
    }

    function packageTarget(target) {
      runJob("/api/package", {target});
    }

    function setPackageButtonBusy(target, busy) {
      const spec = PACKAGE_BUTTON_SPECS.find(item => item.target === target);
      if (!spec) return;
      const btn = document.getElementById(spec.id);
      if (!btn) return;
      btn.disabled = !!busy;
      if (busy) {
        btn.textContent = `Generating ${spec.filename}...`;
      }
    }

    function setMgmtConnectionState(connected, host = "", port = "") {
      mgmtConnected = !!connected;
      mgmtConnectionState.textContent = connected ? `Connected (${host}:${port})` : "Disconnected";
      mgmtConnectionState.classList.toggle("muted", !connected);
      mgmtConnectBtn.disabled = connected;
      mgmtDisconnectBtn.disabled = !connected;
      mgmtConnectedArea.style.display = connected ? "block" : "none";
    }

    function connectManagement() {
      mgmtOutput.textContent = "Connecting...";
      mgmtConnectBtn.disabled = true;
      mgmtDisconnectBtn.disabled = true;
      setMgmtMessage("Attempting connection...", "pending");
      api("/api/management/connect", {
        host: mgmtHost.value.trim(),
        port: mgmtPort.value.trim(),
        password: mgmtPassword.value,
      }).then(status => {
        setMgmtConnectionState(Boolean(status.connected), status.host || "", status.port || "");
        mgmtOutput.textContent = status.banner || "Connected.";
        setMgmtMessage(`Connected to ${status.host}:${status.port}`, "ok");
        mgmtEvents.textContent = "Realtime stream connected.\n";
        mgmtEventCursor = 0;
        pollManagementEvents();
        refreshManagementClients();
      }).catch(err => {
        setMgmtConnectionState(false);
        setMgmtMessage(`Connection failed: ${err.message}`, "err");
        mgmtOutput.textContent = `Error: ${err.message}`;
      });
    }

    function disconnectManagement() {
      api("/api/management/disconnect", {}).then(() => {
        setMgmtConnectionState(false);
        setMgmtMessage("Disconnected.", "muted");
        mgmtOutput.textContent = "Disconnected.";
      }).catch(err => {
        mgmtOutput.textContent = `Error: ${err.message}`;
      });
    }

    function configureRealtimeStream() {
      api("/api/management/realtime", {
        state_on: !!mgmtStateOn.checked,
        log_on: !!mgmtLogOn.checked,
        bytecount_interval: parseInt(mgmtBytecountInterval.value || "0", 10) || 0,
      }).then(result => {
        const summary = (result.results || []).map(item => `${item.command}: ${item.response || "ok"}`).join("\n");
        mgmtOutput.textContent = summary || "Realtime settings applied.";
      }).catch(err => {
        mgmtOutput.textContent = `Error: ${err.message}`;
      });
    }

    function refreshManagementClients() {
      if (!mgmtConnected) {
        mgmtClientCount.textContent = "0";
        mgmtTotalRx.textContent = "0 B";
        mgmtTotalTx.textContent = "0 B";
        mgmtClientTable.innerHTML = `<tr><td class="muted" colspan="6">Not connected.</td></tr>`;
        return;
      }
      api("/api/management/clients").then(data => {
        const clients = data.clients || [];
        const totalRx = clients.reduce((sum, cli) => sum + (Number(cli.bytes_received) || 0), 0);
        const totalTx = clients.reduce((sum, cli) => sum + (Number(cli.bytes_sent) || 0), 0);
        mgmtClientCount.textContent = String(clients.length);
        mgmtTotalRx.textContent = fmtBytes(totalRx);
        mgmtTotalTx.textContent = fmtBytes(totalTx);
        if (!clients.length) {
          mgmtClientTable.innerHTML = `<tr><td class="muted" colspan="6">No connected clients.</td></tr>`;
          return;
        }
        mgmtClientTable.innerHTML = clients.map(cli => `
          <tr>
            <td>${cli.common_name || ""}</td>
            <td>${cli.real_address || ""}</td>
            <td>${cli.virtual_address || ""}</td>
            <td>${cli.bytes_received || 0}</td>
            <td>${cli.bytes_sent || 0}</td>
            <td><button type="button" class="danger" onclick="killManagementClient('${(cli.common_name || "").replace(/'/g, "\\'")}')">Kill</button></td>
          </tr>
        `).join("");
      }).catch(err => {
        mgmtClientCount.textContent = "0";
        mgmtTotalRx.textContent = "0 B";
        mgmtTotalTx.textContent = "0 B";
        mgmtClientTable.innerHTML = `<tr><td class="muted" colspan="6">Error: ${err.message}</td></tr>`;
      });
    }

    function killManagementClient(target) {
      if (!target) return;
      api("/api/management/kill", {target}).then(data => {
        mgmtOutput.textContent = `kill ${data.target}\n${data.response || ""}`;
        refreshManagementClients();
      }).catch(err => {
        mgmtOutput.textContent = `Error: ${err.message}`;
      });
    }

    function pollManagementEvents() {
      api(`/api/management/events?since=${mgmtEventCursor}`).then(data => {
        const events = data.events || [];
        if (events.length) {
          mgmtEventCursor = events[events.length - 1].id;
          const lines = events.map(evt => `[${evt.type}] ${evt.line}`).join("\n");
          mgmtEvents.textContent = (mgmtEvents.textContent + "\n" + lines).trim();
          const maxChars = 16000;
          if (mgmtEvents.textContent.length > maxChars) {
            mgmtEvents.textContent = mgmtEvents.textContent.slice(-maxChars);
          }
        }
      }).catch(() => {
        // Ignore poll errors while disconnected.
      });
    }

    function refreshManagementStatus() {
      api("/api/management/status").then(status => {
        setMgmtConnectionState(Boolean(status.connected), status.host || "", status.port || "");
        if (status.connected) {
          setMgmtMessage(`Connected to ${status.host}:${status.port}`, "ok");
        } else if (!mgmtConnectMessage.textContent.includes("failed")) {
          setMgmtMessage("Not connected.", "muted");
        }
      }).catch(() => {
        setMgmtConnectionState(false);
      });
    }

    function runManagementCommand(command) {
      const cmd = (command || mgmtCommand.value || "").trim();
      if (!cmd) {
        mgmtOutput.textContent = "Please enter a management command.";
        return;
      }
      mgmtCommand.value = cmd;
      mgmtOutput.textContent = "Running command...";
      api("/api/management/command", {command: cmd}).then(data => {
        mgmtOutput.textContent = [
          `--- Response to: ${data.command} ---\n${data.response || "(no output)"}`,
        ].filter(Boolean).join("\n\n");
        if (cmd.toLowerCase().startsWith("status")) {
          refreshManagementClients();
        }
      }).catch(err => {
        mgmtOutput.textContent = `Error: ${err.message}`;
      });
    }

    function runJob(path, payload) {
      if (activeJobPath) {
        setClientActionMessage("Please wait for the current operation to finish.", "muted");
        return;
      }
      api(path, payload).then(data => {
        activeJob = data.job_id;
        activeJobPath = path;
        if (path === "/api/initialize" || path === "/api/reinitialize") {
          initDoneCloseBtn.style.display = "none";
          initProgressLabel.textContent = path === "/api/reinitialize" ? "Re-Initialization is running..." : "Initialization is running...";
          initProgressOutput.textContent = "Running...";
          initProgressBar.className = "progress-bar running";
        } else if (path === "/api/clients") {
          setAddClientBusy(true);
          setClientActionMessage("Generating client...", "pending");
        } else if (path === "/api/revoke") {
          const targetName = payload && payload.client_name ? payload.client_name : "client";
          setClientActionMessage(`Revoking ${targetName}...`, "pending");
        } else if (path === "/api/package-client-ewon") {
          const targetName = payload && payload.client_name ? payload.client_name : "client";
          setClientActionMessage(`Packaging ${targetName} for Cosy+/Flexy...`, "pending");
        } else if (path === "/api/package") {
          activePackageTarget = payload && payload.target ? String(payload.target).toLowerCase() : "";
          if (activePackageTarget) {
            setPackageButtonBusy(activePackageTarget, true);
          }
        }
        pollJob();
      }).catch(err => {
        if (path === "/api/clients") {
          setAddClientBusy(false);
        }
        if (path === "/api/initialize" || path === "/api/reinitialize") {
          initProgressLabel.textContent = `Failed to start: ${err.message}`;
          initProgressBar.className = "progress-bar failed";
          initProgressOutput.textContent = "";
        } else if (path === "/api/package") {
          const failedTarget = payload && payload.target ? String(payload.target).toLowerCase() : "";
          if (failedTarget) {
            setPackageButtonBusy(failedTarget, false);
          }
          setClientActionMessage(`Failed to start package job: ${err.message}`, "err");
        } else {
          setClientActionMessage(`Failed to start: ${err.message}`, "err");
        }
      });
    }

    function pollJob() {
      if (!activeJob) return;
      api(`/api/jobs/${activeJob}`).then(job => {
        if (activeJobPath === "/api/initialize" || activeJobPath === "/api/reinitialize") {
          initProgressLabel.textContent = `${job.label}: ${job.status}`;
          initProgressOutput.textContent = normalizeJobText([job.output || "", job.error || ""].filter(Boolean).join("\n")) || "No output.";
          if (job.status === "running") {
            initDoneCloseBtn.style.display = "none";
            initProgressBar.className = "progress-bar running";
          } else if (job.status === "complete") {
            initDoneCloseBtn.style.display = "inline-block";
            initProgressBar.className = "progress-bar complete";
          } else if (job.status === "failed") {
            initDoneCloseBtn.style.display = "inline-block";
            initProgressBar.className = "progress-bar failed";
          }
        }
        if (job.status === "running") {
          setTimeout(pollJob, 1200);
        } else {
          if (activeJobPath === "/api/clients") {
            setAddClientBusy(false);
          }
          if (activeJobPath === "/api/package" && activePackageTarget) {
            setPackageButtonBusy(activePackageTarget, false);
            activePackageTarget = "";
          }
          if (job.status === "complete") {
            reinitializeUnlocked = false;
            if (activeJobPath === "/api/initialize" || activeJobPath === "/api/reinitialize") {
              setCrlNotice("");
            }
            if ((activeJobPath === "/api/clients" || activeJobPath === "/api/revoke") && job.result && job.result.warning) {
              setCrlNotice(job.result.warning);
            }
            if (activeJobPath === "/api/clients") {
              const created = (job.result && job.result.created_clients) || [];
              if (created.length) {
                setClientActionMessage(`${created[created.length - 1]} generated successfully`, "ok");
                state.clients = Array.from(new Set([...(state.clients || []), ...created]));
                renderStatus();
                resetAddClientsForm();
              }
            }
            if (activeJobPath === "/api/revoke") {
              const revoked = job.result && job.result.revoked_client;
              if (revoked) {
                state.clients = (state.clients || []).filter(name => name !== revoked);
                setClientActionMessage(`${revoked} revoked successfully`, "ok");
                renderStatus();
              }
            }
            if (activeJobPath === "/api/package-client-ewon") {
              const target = job.result && job.result.client_name;
              if (target) {
                setClientActionMessage(`${target} packaged for Cosy+/Flexy successfully`, "ok");
              }
            }
          } else if (activeJobPath === "/api/clients" || activeJobPath === "/api/revoke" || activeJobPath === "/api/package-client-ewon") {
            const err = String(job.error || "Operation failed.").split("\n")[0];
            setClientActionMessage(err, "err");
          }
          activeJob = null;
          activeJobPath = "";
          refreshStatus();
        }
      });
    }

    function renderStatus() {
      baseDir.textContent = "";  // base_dir is not exposed by the API
      readyDot.classList.toggle("ready", state.initialized);
      if (state.initializing) {
        readyText.textContent = "Initializing";
      } else {
        readyText.textContent = state.initialized ? "Initialized" : "Not initialized";
      }

      statusReadyArea.style.display = state.initialized ? "block" : "none";
      initializeBtn.textContent = state.initialized ? "Re-Initialize Server" : "Initialize Server";
      if (!state.initialized) {
        reinitializeUnlocked = false;
        setCrlNotice("");
      }
      initializeBtn.disabled = (state.initialized && !reinitializeUnlocked) || !isInitializeFormReady();

      const details = state.server_details || {};
      const mtuFixEnabled = Boolean(details.mtu_fix_enabled);
      const mtuSummary = mtuFixEnabled
        ? `Enabled (mssfix ${details.mssfix || "n/a"}, tun-mtu ${details.tun_mtu || "n/a"})`
        : "Disabled";
      serverSummary.innerHTML = state.initialized
        ? `<table><tbody>
            <tr><th>Address</th><td>${details.server_address || ""}</td></tr>
            <tr><th>Port</th><td>${details.port || ""}</td></tr>
            <tr><th>Protocol</th><td>${details.proto || ""}</td></tr>
            <tr><th>Ciphers</th><td>${(details.data_ciphers || []).join(", ")}</td></tr>
            <tr><th>MTU/MSS Fix</th><td>${mtuSummary}</td></tr>
          </tbody></table>
          <div class="actions" style="margin-top:10px;">
            <button type="button" class="warn" onclick="openReinitializeWarning()">Re-Initialize Server</button>
          </div>`
        : `<div class="actions"><button type="button" onclick="openInitializeModal()">Initialize Server</button></div>`;

      const packageButtonsVisible = state.initialized;
      serverPackageActions.style.display = packageButtonsVisible ? "flex" : "none";

      const allDownloads = state.downloads || [];
      const serverPkgByName = new Map(
        allDownloads
          .filter(file => /OpenVPN_Server_(Windows|Linux|FlexEdge|Anybus_Defender)\.zip$/i.test(file.name || ""))
          .map(file => [String(file.name), file])
      );
      PACKAGE_BUTTON_SPECS.forEach(spec => {
        const btn = document.getElementById(spec.id);
        if (!btn) return;
        const pkg = serverPkgByName.get(spec.filename);
        if (pkg && pkg.path) {
          btn.textContent = `Download ${spec.filename}`;
          btn.disabled = false;
          btn.onclick = () => {
            window.location.href = `/api/download?path=${encodeURIComponent(pkg.path)}`;
          };
        } else {
          btn.textContent = spec.generateLabel;
          btn.disabled = false;
          btn.onclick = () => packageTarget(spec.target);
        }
      });
      const windowsPkg = serverPkgByName.get("OpenVPN_Server_Windows.zip");
      if (packageWindowsGuideBtn) {
        packageWindowsGuideBtn.style.display = windowsPkg ? "inline-flex" : "none";
      }
      const linuxPkg = serverPkgByName.get("OpenVPN_Server_Linux.zip");
      if (packageLinuxGuideBtn) {
        packageLinuxGuideBtn.style.display = linuxPkg ? "inline-flex" : "none";
      }
      const flexedgePkg = serverPkgByName.get("OpenVPN_Server_FlexEdge.zip");
      if (packageFlexedgeGuideBtn) {
        packageFlexedgeGuideBtn.style.display = flexedgePkg ? "inline-flex" : "none";
      }
      const anybusDefenderPkg = serverPkgByName.get("OpenVPN_Server_Anybus_Defender.zip");
      if (packageAnybusDefenderGuideBtn) {
        packageAnybusDefenderGuideBtn.style.display = anybusDefenderPkg ? "inline-flex" : "none";
      }

      clientTable.innerHTML = (state.clients || []).map(name => {
        const safePrefix = `clients/${name}/`;
        const files = allDownloads.filter(file => (file.path || "").replace(/\\/g, "/").startsWith(safePrefix));
        const pkgHtml = files.length
          ? files.map(file => `<a class="download" href="/api/download?path=${encodeURIComponent(file.path)}">${file.name.split("/").pop()}</a>`).join(" ")
          : `<span class="muted">No package yet</span>`;
        const safeName = String(name).replace(/'/g, "\\'");
        const deployBtn = `<button type="button" onclick="packageClientEwonByName('${safeName}')">Deploy as Cosy+/Flexy</button>`;
        const ewonHelpBtn = `<button type="button" class="secondary help-btn" onclick="openEwonGuideModal()" title="Open Cosy+/Flexy deployment guide" aria-label="Open Cosy+/Flexy deployment guide">?</button>`;
        const revokeBtn = `<button type="button" class="danger" onclick="revokeClientByName('${safeName}')">Revoke</button>`;
        return `<tr><td>${name}</td><td>${pkgHtml}</td><td class="action-cell"><div class="action-group"><span style="display:inline-flex;align-items:center;gap:6px;">${deployBtn}${ewonHelpBtn}</span>${revokeBtn}</div></td></tr>`;
      }).join("") || `<tr><td class="muted" colspan="3">No clients</td></tr>`;

      subnetTable.innerHTML = (state.subnets || []).map(row => `<tr><td>${row.Name}</td><td>${row.Subnet}</td></tr>`).join("") || `<tr><td class="muted">No subnets</td></tr>`;
      const cert = state.certificate_details || {};
      // Do not clobber in-progress edits while the initialize modal is open.
      if (!initOverlay.classList.contains("show")) {
        serverAddress.value = details.server_address || "";
        serverPort.value = details.port || "1194";
        serverProto.value = details.proto || "udp";
        certC.value = cert.C || "US";
        certST.value = cert.ST || "MO";
        certL.value = cert.L || "Mineral Point";
        certO.value = cert.O || "GregNet";
        certOU.value = cert.OU || "IT";
        certEmail.value = cert.email_address || "admin@example.com";
        enableMtuFix.checked = mtuFixEnabled;
        mssfixValue.value = details.mssfix || "1360";
        tunMtuValue.value = details.tun_mtu || "1428";
        mtuPreset.value = inferMtuPreset(mssfixValue.value, tunMtuValue.value);
        toggleMtuFixFields();
      }

      validateInitClientNames();
      validateAddClientNames();
      validateAddClientSubnets();
      validateMtuSettings();
      checkInitializeReady();
    }

    function renderCiphers() {
      cipherChecks.innerHTML = (state.ciphers || []).map(cipher => {
        const checked = ["AES-256-GCM", "AES-128-GCM"].includes(cipher) ? "checked" : "";
        return `<label class="check"><input class="cipher" type="checkbox" value="${cipher}" ${checked}> ${cipher}</label>`;
      }).join("");
      document.querySelectorAll(".cipher").forEach(cb => cb.addEventListener("change", () => { validateCiphers(); checkInitializeReady(); }));
    }

    function refreshStatus() {
      api("/api/status").then(data => {
        const firstLoad = !state.ciphers;
        state = data;
        if (firstLoad) renderCiphers();
        renderStatus();
      });
    }

    addClientRow("initClients", "client1", "");
    resetAddClientsForm();
    initTheme();
    initProgressBar.className = "progress-bar";
    initProgressLabel.textContent = "No initialization running.";
    initProgressOutput.textContent = "No output yet.";
    setClientActionMessage("");
    refreshStatus();
    refreshManagementStatus();
    setInterval(refreshStatus, 5000);
    setInterval(pollManagementEvents, 1500);
    setInterval(refreshManagementStatus, 5000);
    setInterval(() => {
      if (mgmtConnected) {
        refreshManagementClients();
      }
    }, 5000);

    sectionHelpOverlay.addEventListener("click", (event) => {
      if (event.target === sectionHelpOverlay) {
        closeSectionHelp();
      }
    });
  </script>
</body>
</html>
"""


def _is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _read_instance_lock() -> dict | None:
    try:
        with open(APP_INSTANCE_LOCK, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        return None
    return None


def _remove_instance_lock() -> None:
    try:
        if os.path.exists(APP_INSTANCE_LOCK):
            os.remove(APP_INSTANCE_LOCK)
    except Exception as exc:
        logging.debug(f"Failed to remove app lock file: {exc}")


def _write_instance_lock(port: int) -> None:
    payload = {"pid": os.getpid(), "port": int(port), "started_at": int(time.time())}
    try:
        with open(APP_INSTANCE_LOCK, "w", encoding="utf-8") as f:
            json.dump(payload, f)
    except Exception as exc:
        logging.warning(f"Failed to write app lock file: {exc}")


def _stop_previous_instance_if_needed() -> None:
    lock = _read_instance_lock()
    if not lock:
        return

    prev_pid = int(lock.get("pid") or 0)
    if not _is_pid_running(prev_pid):
        _remove_instance_lock()
        return

    if prev_pid == os.getpid():
        return

    logging.info(f"Stopping previous EZ OpenVPN Toolkit Web instance (PID {prev_pid}).")
    try:
        os.kill(prev_pid, signal.SIGTERM)
    except Exception as exc:
        logging.warning(f"Unable to stop previous instance PID {prev_pid}: {exc}")
        return

    deadline = time.time() + 5
    while time.time() < deadline:
        if not _is_pid_running(prev_pid):
            break
        time.sleep(0.1)

    if _is_pid_running(prev_pid):
        logging.warning(f"Previous instance PID {prev_pid} is still running.")
    else:
        _remove_instance_lock()


def _start_idle_shutdown_watcher(server: ThreadingHTTPServer) -> None:
    def _watch() -> None:
        while True:
            time.sleep(5)
            idle_for = time.time() - _LAST_ACTIVITY_TS
            if idle_for >= _IDLE_SHUTDOWN_SECONDS:
                logging.info(
                    f"No web activity for {int(idle_for)}s; shutting down UI server."
                )
                with contextlib.suppress(Exception):
                    server.shutdown()
                break

    threading.Thread(target=_watch, daemon=True).start()


def _request_app_exit(server: ThreadingHTTPServer) -> None:
  logging.info("App shutdown requested from Web UI.")

  def _terminate_pid_windows(pid: int) -> bool:
    if os.name != "nt" or pid <= 0:
      return False
    process_terminate = 0x0001
    handle = ctypes.windll.kernel32.OpenProcess(process_terminate, False, int(pid))
    if not handle:
      return False
    try:
      return bool(ctypes.windll.kernel32.TerminateProcess(handle, 1))
    finally:
      ctypes.windll.kernel32.CloseHandle(handle)

  def _do_exit() -> None:
    trace_paths = [
      os.path.join(BASE_DIR, "exit_trace.log"),
      os.path.join(os.environ.get("TEMP", "C:\\Temp"), "exit_trace.log"),
    ]

    def _trace(msg: str) -> None:
      line = f"[{time.strftime('%H:%M:%S')}] {msg}"
      for p in trace_paths:
        with contextlib.suppress(Exception):
          with open(p, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _run_cmd(cmd: list[str], timeout_sec: int = 6) -> None:
      try:
        result = subprocess.run(
          cmd,
          capture_output=True,
          text=True,
          timeout=timeout_sec,
          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if len(stdout) > 300:
          stdout = stdout[:300] + "..."
        if len(stderr) > 300:
          stderr = stderr[:300] + "..."
        _trace(f"CMD rc={result.returncode}: {' '.join(cmd)}")
        if stdout:
          _trace(f"CMD stdout: {stdout}")
        if stderr:
          _trace(f"CMD stderr: {stderr}")
      except Exception as exc:
        _trace(f"CMD exception for {' '.join(cmd)}: {exc}")

    # Allow API response delivery before triggering shutdown.
    time.sleep(0.5)
    if os.name == "nt":
      exe_name = os.path.basename(sys.executable)
      script_path = _resolve_runtime_asset_path("exit_app.ps1")
      system_root = os.environ.get("SystemRoot", r"C:\Windows")
      taskkill_exe = os.path.join(system_root, "System32", "taskkill.exe")
      powershell_exe = os.path.join(
        system_root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"
      )

      _trace(
        f"Exit start: pid={os.getpid()} ppid={os.getppid()} exe={sys.executable}"
      )
      _trace(f"script_path={script_path}")
      _trace(f"taskkill_exe={taskkill_exe}")
      _trace(f"powershell_exe={powershell_exe}")

      # First try the helper script (known-good when run manually).
      if os.path.isfile(script_path):
        _run_cmd(
          [
            powershell_exe if os.path.isfile(powershell_exe) else "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script_path,
            "-ExeName",
            exe_name,
            "-DelayMs",
            "900",
          ],
          timeout_sec=8,
        )
      else:
        _trace("exit_app.ps1 was not found at runtime")

      # Additional hard fallbacks.
      taskkill_cmd = taskkill_exe if os.path.isfile(taskkill_exe) else "taskkill"
      _run_cmd([taskkill_cmd, "/F", "/IM", exe_name], timeout_sec=4)
      _run_cmd([taskkill_cmd, "/F", "/PID", str(os.getppid()), "/T"], timeout_sec=4)
      _run_cmd([taskkill_cmd, "/F", "/PID", str(os.getpid())], timeout_sec=4)

      # WinAPI hard-stop fallback in case taskkill is blocked or constrained.
      with contextlib.suppress(Exception):
        ok = _terminate_pid_windows(os.getppid())
        _trace(f"TerminateProcess(ppid={os.getppid()}) -> {ok}")
      with contextlib.suppress(Exception):
        ok = _terminate_pid_windows(os.getpid())
        _trace(f"TerminateProcess(pid={os.getpid()}) -> {ok}")

    # Final fallback on any platform.
    time.sleep(5)
    logging.warning("Forced process exit after shutdown timeout.")
    os._exit(0)

  threading.Thread(target=_do_exit, daemon=True).start()


def _prompt_port_styled(default_port: int) -> int | None:
  import tkinter as tk

  root = tk.Tk()
  root.withdraw()

  dialog = tk.Toplevel(root)
  dialog.title("EZ OpenVPN Toolkit")
  dialog.resizable(False, False)
  dialog.attributes("-topmost", True)
  dialog.configure(bg="#0f1b2a")

  icon_path = _resolve_runtime_icon_path()
  if icon_path:
    with contextlib.suppress(Exception):
      root.iconbitmap(icon_path)
    with contextlib.suppress(Exception):
      dialog.iconbitmap(icon_path)

  # Keep startup prompt visually aligned with the app's look.
  frame = tk.Frame(dialog, bg="#0f1b2a", padx=16, pady=14)
  frame.pack(fill="both", expand=True)

  title = tk.Label(
    frame,
    text="Web UI Port",
    bg="#0f1b2a",
    fg="#e7eef8",
    font=("Segoe UI Semibold", 12),
  )
  title.pack(anchor="w")

  subtitle = tk.Label(
    frame,
    text="Enter TCP port (1-65535)",
    bg="#0f1b2a",
    fg="#a9bad0",
    font=("Segoe UI", 9),
  )
  subtitle.pack(anchor="w", pady=(2, 8))

  value_var = tk.StringVar(value=str(default_port))
  entry = tk.Entry(
    frame,
    textvariable=value_var,
    width=12,
    bg="#0b1420",
    fg="#f1f5fb",
    insertbackground="#f1f5fb",
    relief="flat",
    highlightthickness=1,
    highlightbackground="#2d3f57",
    highlightcolor="#2d8aa0",
    font=("Consolas", 12),
  )
  entry.pack(anchor="w", fill="x")
  entry.select_range(0, "end")
  entry.focus_set()

  error_var = tk.StringVar(value="")
  error_label = tk.Label(
    frame,
    textvariable=error_var,
    bg="#0f1b2a",
    fg="#ff8a8a",
    font=("Segoe UI", 8),
  )
  error_label.pack(anchor="w", pady=(6, 0))

  result = {"port": None}

  def _submit() -> None:
    raw = value_var.get().strip()
    if not raw.isdigit():
      error_var.set("Port must be a number.")
      return
    candidate = int(raw)
    if candidate < 1 or candidate > 65535:
      error_var.set("Port must be between 1 and 65535.")
      return
    result["port"] = candidate
    dialog.destroy()

  def _cancel() -> None:
    dialog.destroy()

  buttons = tk.Frame(frame, bg="#0f1b2a")
  buttons.pack(fill="x", pady=(10, 0))

  ok_btn = tk.Button(
    buttons,
    text="Start",
    command=_submit,
    bg="#1f8da6",
    fg="#ffffff",
    activebackground="#18738a",
    activeforeground="#ffffff",
    relief="flat",
    padx=14,
    pady=4,
    font=("Segoe UI Semibold", 9),
  )
  ok_btn.pack(side="left")

  cancel_btn = tk.Button(
    buttons,
    text="Cancel",
    command=_cancel,
    bg="#2a3648",
    fg="#d7e1ef",
    activebackground="#233243",
    activeforeground="#d7e1ef",
    relief="flat",
    padx=14,
    pady=4,
    font=("Segoe UI", 9),
  )
  cancel_btn.pack(side="left", padx=(8, 0))

  dialog.bind("<Return>", lambda _evt: _submit())
  dialog.bind("<Escape>", lambda _evt: _cancel())
  dialog.protocol("WM_DELETE_WINDOW", _cancel)

  dialog.update_idletasks()
  width = max(dialog.winfo_width(), 420)
  height = dialog.winfo_height()
  dialog.minsize(width, height)
  x = (dialog.winfo_screenwidth() - width) // 2
  y = (dialog.winfo_screenheight() - height) // 2
  dialog.geometry(f"{width}x{height}+{x}+{y}")

  dialog.grab_set()
  root.wait_window(dialog)
  root.destroy()
  return result["port"]


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    setup_logging()
    _stop_previous_instance_if_needed()

    if getattr(sys, "frozen", False):
      try:
        chosen = _prompt_port_styled(port)
        if chosen is not None:
          port = int(chosen)
      except Exception:
        # Fall back to default port if popup fails.
        pass

    server = None
    last_error = None
    for candidate in range(port, port + 20):
        try:
            server = ThreadingHTTPServer((host, candidate), ToolkitHandler)
            port = candidate
            break
        except OSError as exc:
            last_error = exc
            continue
    if server is None:
        raise OSError(f"No available local port found for the Web GUI: {last_error}")

    _touch_activity()
    _write_instance_lock(port)
    atexit.register(_remove_instance_lock)
    _start_idle_shutdown_watcher(server)

    url = f"http://{host}:{port}/"
    print(f"EZ OpenVPN Toolkit Web GUI is running at {url}")
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    finally:
        _remove_instance_lock()
        with contextlib.suppress(Exception):
            server.server_close()


if __name__ == "__main__":
    run()
