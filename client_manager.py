# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# client_manager.py

import os
import logging
import shutil
from helpers import run_command, get_base_dir, create_directory, sanitize_subj_field
from config import OPENSSL_PATH
from openvpn_config import (
    update_timestamp,
    generate_client_ovpn,
    regenerate_server_conf,
)
from subnet_management import (
    load_existing_subnets,
    validate_subnet,
    save_subnet_to_csv,
    remove_client_from_csv,
    get_subnet_by_name,
)

BASE_DIR = get_base_dir()
CLIENTS_DIR = os.path.join(BASE_DIR, "clients")
SERVER_DIR = os.path.join(BASE_DIR, "server")


def manage_client_creation(
    client_name,
    ca_dir,
    common_details,
    openssl_cnf_path,
    server_conf_path,
    ccd_dir,
    openvpn_tunnel_subnet,
    server_address,
    port,
    proto,
    cipher,
    data_ciphers,
    client_subnet_input=None,
    prompt_for_subnet=True,
):
    """
    Manages the creation of client certificates and configurations.
    """
    try:
        client_folder = os.path.join(CLIENTS_DIR, client_name)
        os.makedirs(client_folder, exist_ok=True)

        # Generate client key
        client_key_path = os.path.join(client_folder, f"{client_name}.key")
        run_command([OPENSSL_PATH, "genrsa", "-out", client_key_path, "4096"])
        logging.info(f"Client key generated at: {client_key_path}")

        # Generate client CSR
        client_csr_path = os.path.join(client_folder, f"{client_name}.csr")
        subject = (
            f"/C={sanitize_subj_field(common_details['C'], 'C')}"
            f"/ST={sanitize_subj_field(common_details['ST'], 'ST')}"
            f"/L={sanitize_subj_field(common_details['L'], 'L')}"
            f"/O={sanitize_subj_field(common_details['O'], 'O')}"
            f"/OU={sanitize_subj_field(common_details['OU'], 'OU')}"
            f"/CN={sanitize_subj_field(client_name, 'CN')}"
            f"/emailAddress={sanitize_subj_field(common_details['email_address'], 'email_address')}"
        )
        run_command(
            [
                OPENSSL_PATH,
                "req",
                "-new",
                "-key",
                client_key_path,
                "-out",
                client_csr_path,
                "-subj",
                subject,
                "-config",
                openssl_cnf_path,
            ]
        )
        logging.info(f"Client CSR generated at: {client_csr_path}")

        # Sign client certificate
        client_crt_path = os.path.join(client_folder, f"{client_name}.crt")
        run_command(
            [
                OPENSSL_PATH,
                "ca",
                "-batch",
                "-config",
                openssl_cnf_path,
                "-in",
                client_csr_path,
                "-out",
                client_crt_path,
                "-days",
                "3650",
                "-notext",
                "-md",
                "sha256",
            ]
        )
        logging.info(f"Client certificate signed at: {client_crt_path}")

        # Generate client configuration
        ta_key_path = os.path.join(SERVER_DIR, "ta.key")
        ca_crt_path = os.path.join(ca_dir, "ca.crt")
        generate_client_ovpn(
            client_name,
            client_folder,
            ca_crt_path,
            client_crt_path,
            client_key_path,
            ta_key_path,
            server_address,
            port,
            proto,
            cipher,
            data_ciphers,
        )
        logging.info(f"Client {client_name} configuration generated.")

        if client_subnet_input:
            has_subnet = "y"
        elif prompt_for_subnet:
            # Ask if client has a subnet to push over VPN
            while True:
                has_subnet = (
                    input(
                        f"Does client {client_name} have a subnet to push over the VPN tunnel? (y/n): "
                    )
                    .strip()
                    .lower()
                )
                if has_subnet in ["y", "n"]:
                    break
                else:
                    print("Invalid input. Please enter 'y' or 'n'.")
        else:
            has_subnet = "n"

        if has_subnet == "y":
            while True:
                try:
                    if prompt_for_subnet and not client_subnet_input:
                        client_subnet_input = input(
                            f"Enter the subnet for client {client_name} (e.g., 10.255.254.0/24): "
                        ).strip()
                    # Load existing subnets and validate the client subnet
                    existing_subnets = load_existing_subnets(
                        os.path.join(BASE_DIR, "subnets.csv")
                    )
                    client_subnet = validate_subnet(
                        client_subnet_input, existing_subnets
                    )
                    logging.info(f"Validated client subnet: {client_subnet}")
                    break  # Exit the loop if validation is successful
                except ValueError as e:
                    if not prompt_for_subnet:
                        raise
                    print(f"Error: {e}. Please try again.")
                    client_subnet_input = None

            # Save the client subnet to subnets.csv
            save_subnet_to_csv(
                os.path.join(BASE_DIR, "subnets.csv"), client_name, client_subnet
            )
            logging.info(f"Saved subnet for client {client_name} to subnets.csv")
            existing_subnets.append(str(client_subnet))

            # Create client-specific CCD file
            try:
                # Ensure CCD directory exists
                os.makedirs(ccd_dir, exist_ok=True)
                ccd_file_path = os.path.join(ccd_dir, client_name)
                with open(ccd_file_path, "w") as ccd_file:
                    ccd_file.write(
                        f"iroute {client_subnet.network_address} {client_subnet.netmask}\n"
                    )
                logging.info(
                    f"CCD file for client {client_name} written at {ccd_file_path}"
                )
            except Exception as e:
                logging.error(
                    f"Failed to create CCD file for client {client_name}: {e}"
                )
                print(
                    f"Failed to create CCD file for client {client_name}. Check the logs for more details."
                )

        else:
            logging.info(f"Client {client_name} does not have a subnet to push.")
            # No need to update server configuration or create CCD file

        # Always update the timestamp in server configuration
        update_timestamp(server_conf_path)
        logging.info(
            f"Server configuration timestamp updated after adding client {client_name}."
        )

        # Read server_lan_subnet from subnets.csv
        server_lan_subnet = get_subnet_by_name(
            os.path.join(BASE_DIR, "subnets.csv"), "server_local_private_subnet"
        )
        if not server_lan_subnet:
            logging.info("Server LAN subnet not found in subnets.csv; continuing without server LAN route.")

        # Copy crl.pem from ca dir to server_conf_path
        crl_source_path = os.path.join(ca_dir, "crl.pem")
        crl_dest_path = os.path.join(os.path.dirname(server_conf_path), "crl.pem")
        try:
            shutil.copy(crl_source_path, crl_dest_path)
            logging.info(f"Copied crl.pem from {crl_source_path} to {crl_dest_path}")
        except Exception as e:
            logging.error(f"Failed to copy crl.pem: {e}")
            raise

        # Regenerate the server configuration to re-inline the updated CRL and include client subnets
        regenerate_server_conf(
            server_conf_path,
            openvpn_tunnel_subnet,
            os.path.join(ca_dir, "ca.crt"),
            os.path.join(os.path.dirname(server_conf_path), "server.crt"),
            os.path.join(os.path.dirname(server_conf_path), "server.key"),
            os.path.join(os.path.dirname(server_conf_path), "dh.pem"),
            ta_key_path,
            os.path.join(os.path.dirname(server_conf_path), "crl.pem"),
            port,
            proto,
            cipher,
            data_ciphers,
            server_lan_subnet,
            ccd_dir,
        )
        logging.info(
            f"Server configuration regenerated with updated CRL and client subnets after adding client {client_name}."
        )

    except Exception as e:
        logging.error(f"Failed to create client {client_name}: {e}")
        print(
            f"Failed to create client {client_name}. Check the logs for more details."
        )


def list_current_clients():
    """
    Lists all the current clients by reading the clients directory.
    """
    if not os.path.exists(CLIENTS_DIR):
        return []
    return [
        client
        for client in os.listdir(CLIENTS_DIR)
        if os.path.isdir(os.path.join(CLIENTS_DIR, client))
    ]
