# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# Software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# client_cert.py

import os
import logging
from helpers import run_command, run_command_with_progress
from config import OPENSSL_PATH


def generate_client_key(client_key_path: str) -> None:
    """
    Generates a client key (4096-bit RSA) with progress indicator.
    """
    try:
        run_command_with_progress(
            [OPENSSL_PATH, "genrsa", "-out", client_key_path, "4096"],
            "Generating 4096-bit client private key",
        )
        logging.info(f"Client key generated at: {client_key_path}")
    except Exception as e:
        logging.error(f"Failed to generate client key: {e}")
        raise


def generate_client_csr(
    client_key_path: str,
    client_csr_path: str,
    client_name: str,
    common_details: dict,
    openssl_cnf_path: str,
) -> None:
    """
    Generates a client CSR.
    """
    try:
        subject = (
            f"/C={common_details['C']}"
            f"/ST={common_details['ST']}"
            f"/L={common_details['L']}"
            f"/O={common_details['O']}"
            f"/OU={common_details['OU']}"
            f"/CN={client_name}"
            f"/emailAddress={common_details['email_address']}"
        )
        run_command(
            [
                OPENSSL_PATH, "req", "-new",
                "-key", client_key_path,
                "-out", client_csr_path,
                "-subj", subject,
                "-config", openssl_cnf_path,
            ]
        )
        logging.info(f"Client CSR generated at: {client_csr_path}")
    except Exception as e:
        logging.error(f"Failed to generate client CSR: {e}")
        raise


def sign_client_certificate(client_csr_path: str, client_crt_path: str, openssl_cnf_path: str) -> None:
    """
    Signs a client certificate with the CA.
    """
    try:
        run_command(
            [
                OPENSSL_PATH, "ca", "-batch",
                "-config", openssl_cnf_path,
                "-extensions", "client_cert",
                "-in", client_csr_path,
                "-out", client_crt_path,
                "-days", "3650",
                "-notext",
                "-md", "sha256",
            ]
        )
        logging.info(f"Client certificate signed at: {client_crt_path}")
    except Exception as e:
        logging.error(f"Failed to sign client certificate: {e}")
        raise
