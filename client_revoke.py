# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# client_revoke.py

import os
import logging
import shutil
from helpers import run_command, get_base_dir, ensure_openssl_ca_dir
from config import OPENSSL_PATH
from openvpn_config import regenerate_server_conf
from subnet_management import remove_client_from_csv, get_subnet_by_name
import json

BASE_DIR = get_base_dir()


def revoke_client(client_name, ca_dir, openssl_cnf_path, subnets_csv):
    """Revokes a client's certificate and updates the CRL."""
    try:
        client_folder = os.path.join(BASE_DIR, "clients", client_name)
        client_cert_path = os.path.join(client_folder, f"{client_name}.crt")
        if not os.path.exists(client_cert_path):
            logging.error(f"Client certificate not found for {client_name}")
            print(f"Client certificate not found for {client_name}")
            return

        # Repair stale absolute CA paths in openssl.cnf after folder moves.
        ensure_openssl_ca_dir(openssl_cnf_path, ca_dir)

        # Revoke the client certificate
        run_command(
            [
                OPENSSL_PATH,
                "ca",
                "-config",
                openssl_cnf_path,
                "-revoke",
                client_cert_path,
            ]
        )
        logging.info(f"Client {client_name} certificate revoked.")

        # Regenerate the CRL
        crl_path = os.path.join(ca_dir, "crl.pem")
        run_command(
            [
                OPENSSL_PATH,
                "ca",
                "-config",
                openssl_cnf_path,
                "-gencrl",
                "-out",
                crl_path,
            ]
        )
        logging.info("CRL updated.")

        # Copy updated CRL to server directory
        server_crl_path = os.path.join(BASE_DIR, "server", "crl.pem")
        shutil.copyfile(crl_path, server_crl_path)
        logging.info(f"CRL copied to {server_crl_path}")

        # Remove client's subnet from subnets.csv if present
        remove_client_from_csv(subnets_csv, client_name)
        logging.info(f"Removed client {client_name} subnet from subnets.csv")

        # Remove client's directory
        if os.path.exists(client_folder):
            shutil.rmtree(client_folder)
            logging.info(f"Removed client directory {client_folder}")

        # Remove client's CCD file if present
        ccd_file = os.path.join(BASE_DIR, "server", "ccd", client_name)
        if os.path.exists(ccd_file):
            os.remove(ccd_file)
            logging.info(f"Removed CCD file {ccd_file}")

        # Remove client from client_names.json
        client_names_json = os.path.join(BASE_DIR, "client_names.json")
        if os.path.exists(client_names_json):
            with open(client_names_json, "r") as f:
                client_names = json.load(f)
            if client_name in client_names:
                client_names.remove(client_name)
                with open(client_names_json, "w") as f:
                    json.dump(client_names, f)
                logging.info(f"Removed client {client_name} from client_names.json")

        # Update the timestamp of the server configuration and regenerate it
        server_conf_path = os.path.join(BASE_DIR, "server", "server.conf")
        ca_crt_path = os.path.join(ca_dir, "ca.crt")
        server_crt_path = os.path.join(BASE_DIR, "server", "server.crt")
        server_key_path = os.path.join(BASE_DIR, "server", "server.key")
        dh_path = os.path.join(BASE_DIR, "server", "dh.pem")
        ta_key_path = os.path.join(BASE_DIR, "server", "ta.key")
        ccd_dir = os.path.join(BASE_DIR, "server", "ccd")

        # Load server details
        server_details_json = os.path.join(BASE_DIR, "server_details.json")
        if not os.path.exists(server_details_json):
            logging.error("Server details not found. Please re-initialize the server.")
            raise Exception("Server details not found.")

        with open(server_details_json, "r") as f:
            server_details = json.load(f)

        port = server_details["port"]
        proto = server_details["proto"]
        cipher = server_details["cipher"]
        data_ciphers = server_details["data_ciphers"]
        mtu_fix_enabled = bool(server_details.get("mtu_fix_enabled", False))
        mssfix_value = server_details.get("mssfix")
        tun_mtu_value = server_details.get("tun_mtu")

        # Load openvpn_tunnel_subnet and server_lan_subnet from subnets.csv
        openvpn_tunnel_subnet = get_subnet_by_name(subnets_csv, "openvpn_tunnel_subnet")
        server_lan_subnet = get_subnet_by_name(
            subnets_csv, "server_local_private_subnet"
        )
        if not openvpn_tunnel_subnet:
            logging.error("OpenVPN tunnel subnet not found in subnets.csv")
            raise Exception("OpenVPN tunnel subnet not found in subnets.csv")
        if not server_lan_subnet:
            logging.info("Server LAN subnet not found in subnets.csv; regenerating without server LAN route.")

        # Regenerate server.conf
        regenerate_server_conf(
            server_conf_path,
            openvpn_tunnel_subnet,
            ca_crt_path,
            server_crt_path,
            server_key_path,
            dh_path,
            ta_key_path,
            server_crl_path,
            port,
            proto,
            cipher,
            data_ciphers,
            server_lan_subnet,
            ccd_dir="ccd",  # Pass the relative path as a string
            mtu_fix_enabled=mtu_fix_enabled,
            mssfix_value=mssfix_value,
            tun_mtu_value=tun_mtu_value,
        )
        logging.info("Server configuration regenerated after client revocation.")

    except Exception as e:
        logging.error(f"Failed to revoke client {client_name}: {e}")
        print(
            f"Failed to revoke client {client_name}. Check the logs for more details."
        )
