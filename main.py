# main.py
# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# Software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import os
import json
import logging
import shutil
import sys
import zipfile

from client_revoke import revoke_client
from config import get_certificate_details, get_base_dir
from ca_setup import setup_ca
from client_manager import list_current_clients, manage_client_creation
from server_cert import generate_server_certificates
from openvpn_config import generate_server_conf
from subnet_management import (
    validate_subnet,
    save_subnet_to_csv,
    load_existing_subnets,
    get_subnet_by_name,
)
from helpers import create_directory
from logger import setup_logging

BASE_DIR = get_base_dir()
setup_logging()

CONFIG_FILE = os.path.join(BASE_DIR, "server_config.json")
CLIENTS_DIR = os.path.join(BASE_DIR, "clients")


def resource_path(relative_path: str) -> str:
    """Get absolute path to a resource, works for PyInstaller and normal execution."""
    try:
        base_path = sys._MEIPASS  # type: ignore[attr-defined]
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


def normalize_openvpn_paths(conf_path: str):
    """
    Replace Windows backslashes with forward slashes for OpenVPN compatibility.
    Prevents escape-character parsing issues in OpenVPN.
    """
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            content = f.read()

        content = content.replace("\\", "/")

        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(content)

        logging.info(f"Normalized OpenVPN paths in {conf_path}")
    except Exception as e:
        logging.error(f"Failed to normalize OpenVPN paths: {e}")
        raise


def validate_server_conf(conf_path: str):
    """
    Basic sanity check before packaging.
    """
    try:
        with open(conf_path, "r", encoding="utf-8") as f:
            content = f.read()

        if "\\" in content:
            print("WARNING: Backslashes still detected in config.")

        if "port " not in content:
            print("WARNING: No 'port' directive found in server.conf")

    except Exception as e:
        logging.error(f"Validation failed: {e}")


def load_server_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return None


def save_server_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f)


def initialize_server():
    try:
        logging.info("Starting OpenVPN server initialization...")

        # Prompt for certificate details
        certificate_details = get_certificate_details()
        certificate_details["server_initialized"] = True
        save_server_config(certificate_details)

        print("\nFinal certificate details:")
        for key, value in certificate_details.items():
            if key != "server_initialized":
                print(f"{key}: {value}")

        # Directories
        server_dir = os.path.join(BASE_DIR, "server")
        ca_dir = os.path.join(BASE_DIR, "ca")
        openssl_cnf_path = os.path.join(ca_dir, "openssl.cnf")

        # Create directories
        create_directory(server_dir)
        ccd_dir_full = os.path.join(server_dir, "ccd")
        create_directory(ccd_dir_full)

        # CA setup
        setup_ca(certificate_details)

        # Subnets
        existing_subnets = load_existing_subnets(os.path.join(BASE_DIR, "subnets.csv"))

        # OpenVPN tunnel subnet
        while True:
            openvpn_tunnel_subnet_input = input(
                "Enter the OpenVPN tunnel subnet (e.g., 10.8.0.0/24): "
            ).strip()
            try:
                openvpn_tunnel_subnet = validate_subnet(
                    openvpn_tunnel_subnet_input, existing_subnets
                )
                break
            except ValueError as e:
                print(f"Error: {e}")
        save_subnet_to_csv(
            os.path.join(BASE_DIR, "subnets.csv"),
            "openvpn_tunnel_subnet",
            openvpn_tunnel_subnet,
        )
        existing_subnets.append(str(openvpn_tunnel_subnet))

        # Server LAN subnet
        while True:
            server_lan_subnet_input = input(
                "Enter the Server LAN subnet (e.g., 192.168.1.0/24): "
            ).strip()
            try:
                server_lan_subnet = validate_subnet(
                    server_lan_subnet_input, existing_subnets
                )
                break
            except ValueError as e:
                print(f"Error: {e}")
        save_subnet_to_csv(
            os.path.join(BASE_DIR, "subnets.csv"),
            "server_local_private_subnet",
            server_lan_subnet,
        )
        existing_subnets.append(str(server_lan_subnet))

        # Server certificates
        common_details = certificate_details.copy()
        generate_server_certificates(
            ca_dir, server_dir, common_details, openssl_cnf_path
        )

        # Clients and server details
        client_names, server_address, port, proto, cipher, data_ciphers = (
            prompt_for_clients()
        )

        server_details = {
            "server_address": server_address,
            "port": port,
            "proto": proto,
            "cipher": cipher,
            "data_ciphers": data_ciphers,
        }
        with open(os.path.join(BASE_DIR, "server_details.json"), "w", encoding="utf-8") as f:
            json.dump(server_details, f)
        logging.info("Server details saved to server_details.json")

        # Generate server.conf
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
            data_ciphers=data_ciphers,
            server_lan_subnet=server_lan_subnet,
            ccd_dir="ccd",  # relative path string as in your existing code
        )

        # Create clients
        for client_name in client_names:
            manage_client_creation(
                client_name,
                ca_dir,
                certificate_details,  # custom cert details
                openssl_cnf_path,
                os.path.join(server_dir, "server.conf"),
                ccd_dir_full,
                openvpn_tunnel_subnet,
                server_address,
                port,
                proto,
                cipher,
                data_ciphers,
            )

        save_server_config(certificate_details)
        logging.info("OpenVPN server initialization completed.")

    except Exception as e:
        logging.error(f"Error during OpenVPN server initialization: {e}")
        print("Failed to initialize the OpenVPN server. Check the logs for more details.")
        print(f"Error: {e}")


def generate_client_certificates():
    try:
        logging.info("Starting Client Certificate and Configuration generation...")

        details_path = os.path.join(BASE_DIR, "server_details.json")
        if not os.path.exists(details_path):
            print("Server details not found. Please re-initialize the server.")
            return
        with open(details_path, "r", encoding="utf-8") as f:
            server_details = json.load(f)

        server_address = server_details["server_address"]
        port = server_details["port"]
        proto = server_details["proto"]
        cipher = server_details["cipher"]
        data_ciphers = server_details["data_ciphers"]

        certificate_details = load_server_config()
        if not certificate_details:
            print("Certificate details not found. Please re-initialize the server.")
            return
        certificate_details.pop("server_initialized", None)

        client_names = prompt_for_clients_existing_server()

        openvpn_tunnel_subnet = get_subnet_by_name(
            os.path.join(BASE_DIR, "subnets.csv"), "openvpn_tunnel_subnet"
        )
        if not openvpn_tunnel_subnet:
            print("OpenVPN tunnel subnet not found. Please re-initialize the server.")
            return

        for client_name in client_names:
            manage_client_creation(
                client_name,
                os.path.join(BASE_DIR, "ca"),
                certificate_details,
                os.path.join(BASE_DIR, "ca", "openssl.cnf"),
                os.path.join(BASE_DIR, "server", "server.conf"),
                os.path.join(BASE_DIR, "server", "ccd"),
                openvpn_tunnel_subnet,
                server_address,
                port,
                proto,
                cipher,
                data_ciphers,
            )
        logging.info("Client Certificates and Configurations generated.")
    except Exception as e:
        logging.error(f"Error during Client Certificate/Configuration generation: {e}")
        print("Failed to generate client certificates. Check the logs for more details.")


def prompt_for_clients():
    """
    Prompt for clients and server details; ensure weakest fallback + data-ciphers.
    Returns: (new_client_names, server_address, port, proto, weakest_cipher, selected_ciphers)
    """
    default_values = {"server_address": "example.com", "port": "1194", "proto": "udp"}

    client_names_json = os.path.join(BASE_DIR, "client_names.json")
    if os.path.exists(client_names_json):
        with open(client_names_json, "r", encoding="utf-8") as f:
            client_names = json.load(f)
    else:
        client_names = []

    # number of clients
    while True:
        try:
            num_clients = int(input("Enter the number of clients to create: "))
            if num_clients <= 0:
                print("Please enter a positive integer.")
                continue
            break
        except ValueError:
            print("Please enter a valid integer.")

    new_client_names = []
    for i in range(num_clients):
        while True:
            client_name = input(f"Enter the name for client {i + 1}: ").strip()
            if not client_name:
                print("Client name cannot be empty.")
                continue
            if client_name in client_names or client_name in new_client_names:
                print("Client name already exists. Please enter a different name.")
                continue
            client_names.append(client_name)
            new_client_names.append(client_name)
            break

    with open(client_names_json, "w", encoding="utf-8") as f:
        json.dump(client_names, f)

    # server details
    server_address = input(
        f"Enter the OpenVPN server address [{default_values['server_address']}]: "
    ).strip() or default_values["server_address"]

    port = input(
        f"Enter the OpenVPN server port [{default_values['port']}]: "
    ).strip() or default_values["port"]

    while True:
        proto = input(
            f"Enter the protocol (tcp/udp) [{default_values['proto']}]: "
        ).strip().lower() or default_values["proto"]
        if proto in ["tcp", "udp"]:
            break
        print("Invalid protocol. Please enter either 'tcp' or 'udp'.")

    # Cipher selection (weakest to strongest)
    valid_ciphers = [
        "DES-EDE3-CBC",
        "BF-CBC",
        "SEED-CBC",
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
    full_ordering = list(valid_ciphers)
    selected_ciphers = []

    print(
        "\nSelect ciphers for data-ciphers one at a time (at least one is required).\n"
        "When done, enter 0 or 'done'."
    )
    while True:
        if not valid_ciphers:
            print("\nNo more ciphers available to select.")
            break
        print("\nAvailable Ciphers:")
        for idx, name in enumerate(valid_ciphers, start=1):
            print(f"{idx}.) {name}")
        if selected_ciphers:
            print(f"\nCiphers currently selected: {', '.join(selected_ciphers)}")
        selection = input("Select a cipher (0 to finish): ").strip().lower()
        if selection in ("0", "done"):
            if selected_ciphers:
                break
            print("You must select at least one cipher.")
            continue
        try:
            sel = int(selection)
            if 1 <= sel <= len(valid_ciphers):
                chosen = valid_ciphers[sel - 1]
                selected_ciphers.append(chosen)
                valid_ciphers.remove(chosen)
                print(f"Selected cipher: {chosen}")
            else:
                print(f"Please enter a number between 1 and {len(valid_ciphers)}.")
        except ValueError:
            print("Invalid input. Please enter a number.")

    weakest_cipher = (
        min(selected_ciphers, key=lambda c: full_ordering.index(c))
        if selected_ciphers
        else None
    )
    return new_client_names, server_address, port, proto, weakest_cipher, selected_ciphers


def prompt_for_clients_existing_server():
    """Prompt for client names for an existing server setup."""
    client_names_json = os.path.join(BASE_DIR, "client_names.json")
    if os.path.exists(client_names_json):
        with open(client_names_json, "r", encoding="utf-8") as f:
            existing = json.load(f)
    else:
        existing = []

    new_client_names = []
    while True:
        try:
            num_clients = int(input("Enter the number of clients to create: "))
            break
        except ValueError:
            print("Please enter a valid number.")

    for i in range(num_clients):
        client_name = input(f"Enter the name for client {i + 1}: ").strip()
        while client_name in existing or client_name in new_client_names or not client_name:
            if not client_name:
                print("Client name cannot be empty.")
            else:
                print("Client name already exists. Please enter a different name.")
            client_name = input(f"Enter the name for client {i + 1}: ").strip()
        new_client_names.append(client_name)

    all_client_names = existing + new_client_names
    with open(client_names_json, "w", encoding="utf-8") as f:
        json.dump(all_client_names, f)

    return new_client_names


def revoke_clients():
    try:
        while True:
            client_names = list_current_clients()
            if not client_names:
                print("No clients found to revoke.")
                break

            print("Current Clients:")
            for idx, client_name in enumerate(client_names, start=1):
                print(f"{idx}.) {client_name}")
            print(f"{len(client_names) + 1}.) Exit")

            selection = input("Please select which client you would like to revoke: ").strip()
            try:
                selection_int = int(selection)
                if 1 <= selection_int <= len(client_names):
                    client_name_to_revoke = client_names[selection_int - 1]
                    confirm = input(
                        f"Are you sure you want to revoke client '{client_name_to_revoke}'? (y/n): "
                    ).lower()
                    if confirm == "y":
                        revoke_client(
                            client_name_to_revoke,
                            os.path.join(BASE_DIR, "ca"),
                            os.path.join(BASE_DIR, "ca", "openssl.cnf"),
                            os.path.join(BASE_DIR, "subnets.csv"),
                        )
                        logging.info(f"Client {client_name_to_revoke} revoked.")
                        print(f"Client '{client_name_to_revoke}' has been revoked.")
                    else:
                        print("Client revocation cancelled.")
                elif selection_int == len(client_names) + 1:
                    print("Exiting client revocation menu.")
                    break
                else:
                    print(f"Please enter a number between 1 and {len(client_names) + 1}.")
            except ValueError:
                print("Invalid input. Please enter a number.")
    except Exception as e:
        logging.error(f"Error during client revocation: {e}")
        print("Failed to revoke the client. Check the logs for more details.")


def package_server_windows():
    try:
        print("Packaging OpenVPN server for deployment on Windows PC...")

        server_dir = os.path.join(BASE_DIR, "server")
        if not os.path.exists(server_dir):
            print("Server directory not found. Please initialize the server first.")
            return

        powershell_script = resource_path("deploy_ovpn_server_on_win10-11.ps1")
        if not os.path.exists(powershell_script):
            print("PowerShell deployment script not found.")
            return

        temp_dir = os.path.join(BASE_DIR, "temp_windows_deploy")
        os.makedirs(temp_dir, exist_ok=True)

        # Copy server directory
        temp_server_dir = os.path.join(temp_dir, "server")
        shutil.copytree(server_dir, temp_server_dir)

        # Normalize and validate server.conf for OpenVPN compatibility
        server_conf_path = os.path.join(temp_server_dir, "server.conf")
        if os.path.exists(server_conf_path):
            normalize_openvpn_paths(server_conf_path)
            validate_server_conf(server_conf_path)

        # Copy PowerShell deployment script
        shutil.copy(powershell_script, temp_dir)

        # Create ZIP package
        zip_filename = os.path.join(BASE_DIR, "OpenVPN_Server_Windows.zip")
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=temp_dir)
                    zipf.write(file_path, arcname)

        print(f"Packaged server files into '{zip_filename}'.")
        logging.info(f"Packaged server for Windows deployment: {zip_filename}")

        shutil.rmtree(temp_dir, ignore_errors=True)

        print("Instructions for Deployment")
        print("1.) Copy OpenVPN_Server_Windows.zip to the Windows PC.")
        print("2.) Extract to a directory of your choice.")
        print("3.) Open PowerShell in that directory.")
        print("4.) Run: powershell -ExecutionPolicy Bypass -File deploy_ovpn_server_on_win10-11.ps1")
        print(r"Server will be deployed to C:\Program Files\OpenVPN\config-auto and started via OpenVPN service.")

    except Exception as e:
        print(f"An error occurred while packaging the server for Windows: {e}")
        logging.error(f"Error packaging server for Windows: {e}")


def package_server_linux():
    try:
        print("Packaging OpenVPN server for deployment on Linux PC...")
        server_dir = os.path.join(BASE_DIR, "server")
        if not os.path.exists(server_dir):
            print("Server directory not found. Please initialize the server first.")
            return

        bash_script = resource_path("deploy_ovpn_server_linux.sh")
        if not os.path.exists(bash_script):
            print("Bash deployment script not found.")
            return

        temp_dir = os.path.join(BASE_DIR, "temp_linux_deploy")
        os.makedirs(temp_dir, exist_ok=True)
        shutil.copytree(server_dir, os.path.join(temp_dir, "server"))
        shutil.copy(bash_script, temp_dir)

        zip_filename = os.path.join(BASE_DIR, "OpenVPN_Server_Linux.zip")
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=temp_dir)
                    zipf.write(file_path, arcname)
        print(f"Packaged server files into '{zip_filename}'.")
        logging.info(f"Packaged server for Linux deployment: {zip_filename}")

        shutil.rmtree(temp_dir, ignore_errors=True)

        print("Instructions for Deployment")
        print("1.) Copy OpenVPN_Server_Linux.zip to the Linux PC.")
        print("2.) Extract and run: chmod +x deploy_ovpn_server_linux.sh && ./deploy_ovpn_server_linux.sh")
        print("Server directory will be deployed to /etc/openvpn/server and firewall set up.")

    except Exception as e:
        print(f"An error occurred while packaging the server for Linux: {e}")
        logging.error(f"Error packaging server for Linux: {e}")


def modify_server_conf_for_flexedge(server_conf_path):
    """
    Modifies the server.conf for FlexEdge: move status/logs/ccd/ipp to /media/sdcard.
    """
    try:
        with open(server_conf_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        new_status_log = "/media/sdcard/openvpn-status.log"
        new_log_append = "/media/sdcard/openvpn.log"
        new_ccd_dir = "/media/sdcard/ccd"
        new_ipp_file = "/media/sdcard/ipp.txt"

        updated_lines = []
        for line in lines:
            if line.startswith("status "):
                updated_lines.append(f"status {new_status_log}\n")
            elif line.startswith("log-append "):
                updated_lines.append(f"log-append {new_log_append}\n")
            elif line.startswith("client-config-dir "):
                updated_lines.append(f"client-config-dir {new_ccd_dir}\n")
            elif line.startswith("ifconfig-pool-persist "):
                updated_lines.append(f"ifconfig-pool-persist {new_ipp_file}\n")
            else:
                updated_lines.append(line)

        with open(server_conf_path, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)

        # ensure artifacts exist
        base = os.path.dirname(server_conf_path)
        for fp in [
            os.path.join(base, "openvpn-status.log"),
            os.path.join(base, "openvpn.log"),
            os.path.join(base, "ipp.txt"),
        ]:
            if not os.path.exists(fp):
                open(fp, "w", encoding="utf-8").close()

        ccd_dir = os.path.join(base, "ccd")
        if not os.path.exists(ccd_dir):
            os.makedirs(ccd_dir, exist_ok=True)

        logging.info(f"Modified server.conf for FlexEdge deployment at {server_conf_path}")
    except Exception as e:
        logging.error(f"Failed to modify server.conf for FlexEdge: {e}")
        raise


def package_server_flexedge():
    try:
        print("Packaging OpenVPN server for deployment on FlexEdge...")
        server_dir = os.path.join(BASE_DIR, "server")
        if not os.path.exists(server_dir):
            print("Server directory not found. Please initialize the server first.")
            return

        temp_dir = os.path.join(BASE_DIR, "temp_flexedge_deploy")
        os.makedirs(temp_dir, exist_ok=True)
        temp_server_dir = os.path.join(temp_dir, "server")
        shutil.copytree(server_dir, temp_server_dir)

        server_conf_path = os.path.join(temp_server_dir, "server.conf")
        modify_server_conf_for_flexedge(server_conf_path)

        shutil.copy(server_conf_path, os.path.join(temp_server_dir, "server.ovpn"))

        files_for_sdcard_dir = os.path.join(temp_dir, "files_for_sdcard")
        os.makedirs(files_for_sdcard_dir, exist_ok=True)

        for f in ["ipp.txt", "openvpn-status.log", "openvpn.log"]:
            shutil.copy(os.path.join(temp_server_dir, f), files_for_sdcard_dir)

        shutil.copytree(
            os.path.join(temp_server_dir, "ccd"),
            os.path.join(files_for_sdcard_dir, "ccd"),
        )

        zip_filename = os.path.join(BASE_DIR, "OpenVPN_Server_FlexEdge.zip")
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for d in dirs:
                    dir_path = os.path.join(root, d)
                    arcname = os.path.relpath(dir_path, start=temp_dir) + "/"
                    zipf.writestr(arcname, "")
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, start=temp_dir)
                    zipf.write(file_path, arcname)

        print(f"Packaged server files into '{zip_filename}'.")
        logging.info(f"Packaged server for FlexEdge deployment: {zip_filename}")

        shutil.rmtree(temp_dir, ignore_errors=True)

        print("Instructions for Deployment")
        print("1.) Extract the zip. Upload server.conf to FlexEdge (see guide).")
        print("2.) Copy files in files_for_sdcard/ to the device MicroSD (E-Drive).")
    except Exception as e:
        print(f"An error occurred while packaging the server for FlexEdge: {e}")
        logging.error(f"Error packaging server for FlexEdge: {e}")

def package_client_ewon():
    """
    Package a selected client for Ewon Cosy/Flexy:
    - Convert inline <tls-auth> to file reference: 'tls-auth /usr/ta.key 1'
    - Copy ta.key from server dir
    - Zip <client>.ovpn + ta.key
    """
    try:
        print("Packaging client for deployment on Ewon Cosy/Flexy...")

        server_dir = os.path.join(BASE_DIR, "server")
        if not os.path.exists(server_dir):
            print("Server directory not found. Please initialize the OpenVPN server first.")
            return

        client_names = list_current_clients()
        if not client_names:
            print("No clients found. Please generate client certificates first.")
            return

        print("\nAvailable Clients:")
        for idx, client_name in enumerate(client_names, start=1):
            print(f"{idx}. {client_name}")
        print(f"{len(client_names) + 1}. Exit")

        while True:
            try:
                choice = int(input("Select a client to package for Ewon Cosy/Flexy: "))
                if 1 <= choice <= len(client_names):
                    client_name = client_names[choice - 1]
                    break
                elif choice == len(client_names) + 1:
                    print("Exiting client packaging menu.")
                    return
                else:
                    print("Invalid choice, please select a valid client.")
            except ValueError:
                print("Please enter a valid number.")

        client_dir = os.path.join(CLIENTS_DIR, client_name)
        client_ovpn_path = os.path.join(client_dir, f"{client_name}.ovpn")
        ta_key_source_path = os.path.join(server_dir, "ta.key")

        if not os.path.exists(client_ovpn_path):
            print(f"Client OVPN file not found for {client_name}.")
            return
        if not os.path.exists(ta_key_source_path):
            print("TLS authentication key (ta.key) not found in server directory.")
            return

        with open(client_ovpn_path, "r", encoding="utf-8") as ovpn_file:
            lines = ovpn_file.readlines()

        with open(client_ovpn_path, "w", encoding="utf-8") as ovpn_file:
            inside_tls_auth = False
            for line in lines:
                if line.strip() == "<tls-auth>":
                    inside_tls_auth = True
                    continue
                elif line.strip() == "</tls-auth>":
                    inside_tls_auth = False
                    continue  # skip the closing tag
                if not inside_tls_auth:
                    ovpn_file.write(line)
            ovpn_file.write("tls-auth /usr/ta.key 1\n")

        print(f"Updated OVPN file for {client_name} to use Ewon-compatible configuration.")

        ta_key_dest_path = os.path.join(client_dir, "ta.key")
        shutil.copy(ta_key_source_path, ta_key_dest_path)
        print(f"Copied ta.key file to {client_dir}.")

        zip_filename = os.path.join(client_dir, f"ewon_flexy-cosy_deploy__{client_name}.zip")
        with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
            zipf.write(client_ovpn_path, arcname=f"{client_name}.ovpn")
            zipf.write(ta_key_dest_path, arcname="ta.key")

        print(f"Packaged client files into '{zip_filename}'.")
        logging.info(f"Packaged client {client_name} for Ewon Cosy/Flexy: {zip_filename}")

    except Exception as e:
        logging.error(f"Error packaging client for Ewon Cosy/Flexy: {e}")
        print("An error occurred while packaging the client. Check logs for details.")


def show_menu():
    cfg = load_server_config()
    initialized = bool(cfg and cfg.get("server_initialized"))
    print("\nOpenVPN Setup Menu:")
    if initialized:
        print("1. Initialize OpenVPN server (Already Initialized) - Disabled")
    else:
        print("1. Initialize OpenVPN server")
    print("2. Generate Additional Client Certificates and Configurations")
    print("3. Revoke existing clients")
    print("4. Package Server for Deployment on Windows PC")
    print("5. Package Server for Deployment on Linux PC")
    print("6. Package Server for Deployment on FlexEdge")
    print("7. Package Client for Deployment on Ewon Cosy/Flexy")
    print("8. Exit")


def main():
    while True:
        show_menu()
        choice = input("Please make a selection: ").strip()

        cfg = load_server_config()
        initialized = bool(cfg and cfg.get("server_initialized"))

        if choice == "1":
            if initialized:
                print("Server already initialized. Option disabled.")
            else:
                initialize_server()
        elif choice == "2":
            generate_client_certificates()
        elif choice == "3":
            revoke_clients()
        elif choice == "4":
            package_server_windows()
        elif choice == "5":
            package_server_linux()
        elif choice == "6":
            package_server_flexedge()
        elif choice == "7":
            package_client_ewon()
        elif choice == "8":
            print("Goodbye.")
            break
        else:
            print("Invalid selection. Please try again.")


if __name__ == "__main__":
    main()
