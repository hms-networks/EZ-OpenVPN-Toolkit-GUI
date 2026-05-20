# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import os
import logging
from helpers import run_command, run_command_with_progress, create_directory, get_base_dir, sanitize_subj_field
from config import OPENSSL_PATH

BASE_DIR = get_base_dir()


def generate_openssl_config(openssl_cnf_path: str, ca_dir: str, common_details: dict) -> None:
    """Generates an OpenSSL configuration file with CA/client/server profiles."""
    try:
        ca_dir_forward = ca_dir.replace("\\", "/")
        with open(openssl_cnf_path, "w", encoding="utf-8") as f:
            f.write(
                f"""
[ ca ]
default_ca = CA_default

[ CA_default ]
dir               = {ca_dir_forward}
certs             = $dir/certs
new_certs_dir     = $dir/newcerts
database          = $dir/index.txt
serial            = $dir/serial
crlnumber         = $dir/crlnumber
RANDFILE          = $dir/.rand

private_key       = $dir/ca.key
certificate       = $dir/ca.crt

default_md        = sha256
preserve          = no
policy            = policy_strict
default_days      = 3650
default_crl_days  = 3650

[ policy_strict ]
countryName             = supplied
stateOrProvinceName     = supplied
organizationName        = supplied
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits        = 4096
prompt              = no
default_md          = sha256
distinguished_name  = req_distinguished_name
string_mask         = utf8only

[ req_distinguished_name ]
C  = {common_details['C']}
ST = {common_details['ST']}
L  = {common_details['L']}
O  = {common_details['O']}
OU = {common_details['OU']}
CN = {common_details.get('CN', 'OpenVPN-CA')}
emailAddress = {common_details['email_address']}

[ server_cert ]
basicConstraints     = CA:FALSE
nsCertType           = server
nsComment            = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage             = critical, digitalSignature, keyEncipherment
extendedKeyUsage     = serverAuth

[ client_cert ]
basicConstraints     = CA:FALSE
nsCertType           = client
nsComment            = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage             = critical, digitalSignature, keyEncipherment
extendedKeyUsage     = clientAuth

[ v3_ca ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints       = critical, CA:true
keyUsage               = critical, cRLSign, keyCertSign
"""
            )
        logging.info(f"OpenSSL configuration file generated at {openssl_cnf_path}")
    except Exception as e:
        logging.error(f"Failed to generate OpenSSL configuration file: {e}")
        raise


def setup_ca(certificate_details: dict) -> None:
    """
    Creates a CA working dir, generates CA key/cert, initializes DB files, and writes an initial CRL.
    """
    try:
        ca_dir = os.path.join(BASE_DIR, "ca")
        create_directory(ca_dir)
        logging.info(f"CA directory created at: {ca_dir}")

        certs_dir = os.path.join(ca_dir, "certs")
        newcerts_dir = os.path.join(ca_dir, "newcerts")
        create_directory(certs_dir)
        create_directory(newcerts_dir)

        # Generate OpenSSL configuration file
        openssl_cnf_path = os.path.join(ca_dir, "openssl.cnf")
        generate_openssl_config(openssl_cnf_path, ca_dir, certificate_details)

        # 1) CA key (4096-bit)
        ca_key_path = os.path.join(ca_dir, "ca.key")
        run_command_with_progress(
            [OPENSSL_PATH, "genrsa", "-out", ca_key_path, "4096"],
            "Generating 4096-bit CA private key",
        )
        logging.info(f"CA key generated at: {ca_key_path}")

        # 2) CA certificate (self-signed, v3_ca)
        ca_cert_path = os.path.join(ca_dir, "ca.crt")
        subject = (
            f"/C={sanitize_subj_field(certificate_details['C'], 'C')}"
            f"/ST={sanitize_subj_field(certificate_details['ST'], 'ST')}"
            f"/L={sanitize_subj_field(certificate_details['L'], 'L')}"
            f"/O={sanitize_subj_field(certificate_details['O'], 'O')}"
            f"/OU={sanitize_subj_field(certificate_details['OU'], 'OU')}"
            f"/CN=ca"
            f"/emailAddress={sanitize_subj_field(certificate_details['email_address'], 'email_address')}"
        )
        run_command_with_progress(
            [
                OPENSSL_PATH, "req", "-new", "-x509", "-days", "3650",
                "-config", openssl_cnf_path,
                "-extensions", "v3_ca",
                "-key", ca_key_path,
                "-out", ca_cert_path,
                "-subj", subject,
            ],
            "Creating CA certificate",
        )
        logging.info(f"CA certificate generated at: {ca_cert_path}")

        # 3) Initialize OpenSSL DB files
        index_file = os.path.join(ca_dir, "index.txt")
        serial_file = os.path.join(ca_dir, "serial")
        crlnumber_file = os.path.join(ca_dir, "crlnumber")

        open(index_file, "w", encoding="utf-8").close()
        with open(serial_file, "w", encoding="utf-8") as f:
            f.write("01\n")
        with open(crlnumber_file, "w", encoding="utf-8") as f:
            f.write("01\n")
        logging.info("OpenSSL database files initialized.")

        # 4) Initial CRL
        crl_path = os.path.join(ca_dir, "crl.pem")
        run_command_with_progress(
            [OPENSSL_PATH, "ca", "-config", openssl_cnf_path, "-gencrl", "-out", crl_path],
            "Generating initial CRL",
        )
        logging.info(f"Initial CRL generated at: {crl_path}")

    except Exception as e:
        logging.error(f"Failed to set up the Certificate Authority: {e}")
        raise
