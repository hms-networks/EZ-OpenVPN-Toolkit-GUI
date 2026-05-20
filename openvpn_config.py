# openvpn_config.py

# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import os
import logging
import zipfile
from datetime import datetime
from helpers import get_base_dir
from subnet_management import get_client_subnets

BASE_DIR = get_base_dir()


def generate_server_conf(
    server_conf_path,
    openvpn_tunnel_subnet,
    ca_crt_path,
    server_crt_path,
    server_key_path,
    dh_path,
    ta_key_path,
    crl_path,
    port,
    proto,
    cipher,
    data_ciphers,
    server_lan_subnet,
    ccd_dir,
):
    """
    Generates the OpenVPN server configuration file with certificates and keys inline,
    and includes client subnets from subnets.csv.
    """
    try:
        # Ensure the cipher is included in data_ciphers
        if cipher not in data_ciphers:
            data_ciphers.insert(0, cipher)

        with open(server_conf_path, "w", encoding="utf-8") as f:
            f.write(
                f"""# OpenVPN Server Configuration
port {port}
proto {proto}
dev tun
topology subnet
ifconfig-pool-persist ipp.txt
client-config-dir {ccd_dir}
client-to-client
keepalive 10 120
persist-tun
persist-key
status openvpn-status.log
log-append openvpn.log
verb 3
mute 20
explicit-exit-notify 1
data-ciphers {':'.join(data_ciphers)}
data-ciphers-fallback {cipher}
key-direction 0
management 0.0.0.0 7505
"""
            )  # Removed leading and trailing newlines

            # Inline certificates and keys
            f.write("### Certificates and Keys in Inline Format ###\n")

            def inline_file(tag, file_path):
                f.write(f"<{tag}>\n")
                with open(file_path, "r", encoding="utf-8") as file_content:
                    f.write(file_content.read())
                f.write(f"</{tag}>\n\n")

            inline_file("ca", ca_crt_path)
            inline_file("cert", server_crt_path)
            inline_file("key", server_key_path)
            inline_file("dh", dh_path)
            inline_file("tls-auth", ta_key_path)
            inline_file("crl-verify", crl_path)  # Inline the CRL

            f.write("### End of Certificates and Keys in Inline Format ###\n")

            # Include the tunnel subnet in Dotted Decimal format with annotation
            network_address = str(openvpn_tunnel_subnet.network_address)
            netmask = str(openvpn_tunnel_subnet.netmask)
            f.write("\n### Subnet Settings ###\n")
            f.write("## VPN Tunnel Subnet ##\n")
            f.write(f"server {network_address} {netmask} # openvpn_tunnel_subnet\n")

            # Include Server LAN Subnet when provided
            if server_lan_subnet:
                server_lan_network_address = str(server_lan_subnet.network_address)
                server_lan_netmask = str(server_lan_subnet.netmask)
                f.write("\n## Server LAN Subnet ##\n")
                f.write(
                    f'push "route {server_lan_network_address} {server_lan_netmask}" # server_local_private_subnet\n'
                )
                f.write(
                    f"route {server_lan_network_address} {server_lan_netmask} # server_local_private_subnet\n"
                )

            # Include Client Subnets
            f.write("\n## Client Subnets ##\n")
            client_subnets = get_client_subnets(os.path.join(BASE_DIR, "subnets.csv"))
            for client_name, client_subnet in client_subnets.items():
                subnet_network = str(client_subnet.network_address)
                subnet_netmask = str(client_subnet.netmask)
                f.write(
                    f'push "route {subnet_network} {subnet_netmask}" # {client_name}_local_private_subnet\n'
                )
                f.write(
                    f"route {subnet_network} {subnet_netmask} # {client_name}_local_private_subnet\n"
                )
            f.write("## End of Client Subnets ##\n")

            # Add the timestamp at the end of the file
            f.write("\n### Timestamp of Server Configuration Creation ###\n")
            f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} #\n")
            f.write("### End of Timestamp of Server Configuration Creation ###\n")

            logging.info(f"Server configuration file generated at {server_conf_path}")
    except Exception as e:
        logging.error(f"Failed to generate server configuration: {e}")
        raise


def generate_client_ovpn(
    client_name,
    client_dir,
    ca_crt_path,
    client_crt_path,
    client_key_path,
    ta_key_path,
    server_address,
    port,
    proto,
    cipher,
    data_ciphers,
):
    """
    Generates both .ovpn and .conf files for the client.
    """
    try:
        # Ensure the cipher is included in data_ciphers
        if cipher not in data_ciphers:
            data_ciphers.insert(0, cipher)

        client_ovpn_path = os.path.join(client_dir, f"{client_name}.ovpn")
        client_conf_path = os.path.join(client_dir, f"{client_name}.conf")

        # Replace backslashes with forward slashes in paths
        ca_crt_path = ca_crt_path.replace("\\", "/")
        client_crt_path = client_crt_path.replace("\\", "/")
        client_key_path = client_key_path.replace("\\", "/")
        ta_key_path = ta_key_path.replace("\\", "/")

        config_content = f"""
client
dev tun
proto {proto}
remote {server_address} {port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher {cipher}
verb 3
mute 20
key-direction 1
"""

        # Write to .conf file with UTF-8 encoding
        with open(client_conf_path, "w", encoding="utf-8") as conf_file:
            conf_file.write(config_content)
            conf_file.write(f"ca ca.crt\n")
            conf_file.write(f"cert {client_name}.crt\n")
            conf_file.write(f"key {client_name}.key\n")
            conf_file.write(f"tls-auth ta.key 1\n")
        logging.info(f"Client .conf file generated at {client_conf_path}")

        # Write a zip bundle: .conf + ca.crt + client cert/key + ta.key
        conf_zip_path = os.path.join(client_dir, f"{client_name}_conf_bundle.zip")
        with zipfile.ZipFile(conf_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.write(client_conf_path, f"{client_name}.conf")
            zf.write(ca_crt_path.replace("/", os.sep), "ca.crt")
            zf.write(client_crt_path.replace("/", os.sep), f"{client_name}.crt")
            zf.write(client_key_path.replace("/", os.sep), f"{client_name}.key")
            zf.write(ta_key_path.replace("/", os.sep), "ta.key")
        logging.info(f"Client .conf bundle zip generated at {conf_zip_path}")

        # Write to .ovpn file with inline certificates
        with open(client_ovpn_path, "w", encoding="utf-8") as ovpn_file:
            ovpn_file.write(config_content)
            ovpn_file.write("<ca>\n")
            with open(ca_crt_path, "r", encoding="utf-8") as f:
                ovpn_file.write(f.read())
            ovpn_file.write("</ca>\n")
            ovpn_file.write("<cert>\n")
            with open(client_crt_path, "r", encoding="utf-8") as f:
                ovpn_file.write(f.read())
            ovpn_file.write("</cert>\n")
            ovpn_file.write("<key>\n")
            with open(client_key_path, "r", encoding="utf-8") as f:
                ovpn_file.write(f.read())
            ovpn_file.write("</key>\n")
            ovpn_file.write("<tls-auth>\n")
            with open(ta_key_path, "r", encoding="utf-8") as f:
                ovpn_file.write(f.read())
            ovpn_file.write("</tls-auth>\n")
        logging.info(f"Client .ovpn file generated at {client_ovpn_path}")

    except Exception as e:
        logging.error(f"Failed to generate client configuration: {e}")
        raise


def update_timestamp(server_conf_path):
    """Removes existing timestamp and adds a new one."""
    try:
        with open(server_conf_path, "r", encoding="utf-8") as f:
            config_lines = f.readlines()

        updated_lines = []
        inside_timestamp = False
        for line in config_lines:
            if line.strip() == "### Timestamp of Server Configuration Creation ###":
                inside_timestamp = True
                updated_lines.append(line)
                updated_lines.append(
                    f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} #\n"
                )
            elif (
                line.strip()
                == "### End of Timestamp of Server Configuration Creation ###"
            ):
                inside_timestamp = False
                updated_lines.append(line)
            elif not inside_timestamp:
                updated_lines.append(line)

        with open(server_conf_path, "w", encoding="utf-8") as f:
            f.writelines(updated_lines)
        logging.info("Server configuration timestamp updated.")
    except Exception as e:
        logging.error(f"Failed to update server configuration timestamp: {e}")
        raise


def regenerate_server_conf(
    server_conf_path,
    openvpn_tunnel_subnet,
    ca_crt_path,
    server_crt_path,
    server_key_path,
    dh_path,
    ta_key_path,
    crl_path,
    port,
    proto,
    cipher,
    data_ciphers,
    server_lan_subnet,
    ccd_dir,
):
    """Regenerates the server configuration to re-inline the updated CRL."""
    generate_server_conf(
        server_conf_path,
        openvpn_tunnel_subnet,
        ca_crt_path,
        server_crt_path,
        server_key_path,
        dh_path,
        ta_key_path,
        crl_path,
        port,
        proto,
        cipher,
        data_ciphers,
        server_lan_subnet,
        ccd_dir="ccd",  # Pass the relative path as a string
    )
    logging.info(f"Server configuration regenerated at {server_conf_path}")
