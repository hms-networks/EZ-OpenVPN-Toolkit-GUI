# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# config.py

import sys
import os
import platform
import shutil


def get_base_dir():
    """Determines the base directory of the application."""
    if getattr(sys, "frozen", False):
        # Running as a bundled executable
        BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
    else:
        # Running in a normal Python environment
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    return BASE_DIR


BASE_DIR = get_base_dir()

# Determine the operating system and set paths accordingly
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# Paths to external binaries
if IS_WINDOWS:
    # Windows - use bundled binaries
    if getattr(sys, "frozen", False):
        OPENSSL_PATH = os.path.join(sys._MEIPASS, "needed_binaries", "openssl.exe")
        OPENVPN_PATH = os.path.join(sys._MEIPASS, "needed_binaries", "openvpn.exe")
    else:
        OPENSSL_PATH = os.path.join(BASE_DIR, "needed_binaries", "openssl.exe")
        OPENVPN_PATH = os.path.join(BASE_DIR, "needed_binaries", "openvpn.exe")
else:
    # Linux/Unix - use system binaries
    # Try to find openssl in system PATH
    OPENSSL_PATH = shutil.which("openssl")
    if OPENSSL_PATH is None:
        OPENSSL_PATH = "/usr/bin/openssl"  # Fallback to common location
    
    # Try to find openvpn in system PATH
    OPENVPN_PATH = shutil.which("openvpn")
    if OPENVPN_PATH is None:
        OPENVPN_PATH = "/usr/sbin/openvpn"  # Fallback to common location

# Verify that binaries exist
if not os.path.exists(OPENSSL_PATH) and not shutil.which(os.path.basename(OPENSSL_PATH)):
    print(f"WARNING: OpenSSL not found at {OPENSSL_PATH}")
    print("Please install OpenSSL:")
    if IS_LINUX:
        print("  Ubuntu/Debian: sudo apt-get install openssl")
        print("  Fedora/RHEL: sudo dnf install openssl")

if not os.path.exists(OPENVPN_PATH) and not shutil.which(os.path.basename(OPENVPN_PATH)):
    print(f"WARNING: OpenVPN not found at {OPENVPN_PATH}")
    print("Please install OpenVPN:")
    if IS_LINUX:
        print("  Ubuntu/Debian: sudo apt-get install openvpn")
        print("  Fedora/RHEL: sudo dnf install openvpn")

# Common certificate details (defaults)
COMMON_DETAILS = {
    "C": "US",
    "ST": "MO",
    "L": "Mineral Point",
    "O": "GregNet",
    "OU": "IT",
    "email_address": "admin@example.com",
}


def get_user_input(prompt, default):
    """Helper function to get input from user, with a default option."""
    user_input = input(f"{prompt} [{default}]: ")
    return user_input if user_input else default


def get_certificate_details():
    """Prompt user for certificate details or use defaults."""
    while True:
        c_code = get_user_input("Country Name (2 letter code)", COMMON_DETAILS["C"])
        if len(c_code) == 2 and c_code.isalpha():
            break
        else:
            print("Error: Country code must be exactly 2 letters. Please try again.")
    user_details = {
        "C": c_code,
        "ST": get_user_input(
            "State or Province Name (full name)", COMMON_DETAILS["ST"]
        ),
        "L": get_user_input("Locality Name (eg, city)", COMMON_DETAILS["L"]),
        "O": get_user_input("Organization Name (eg, company)", COMMON_DETAILS["O"]),
        "OU": get_user_input(
            "Organizational Unit Name (eg, section)", COMMON_DETAILS["OU"]
        ),
        "email_address": get_user_input(
            "Email Address", COMMON_DETAILS["email_address"]
        ),
    }
    return user_details
