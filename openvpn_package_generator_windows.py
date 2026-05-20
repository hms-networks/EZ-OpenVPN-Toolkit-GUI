#!/bin/python3

# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# openvpn_package_generator_windows.py

import os
import zipfile

# Find the file in the current directory that begins with OpenVPN_Cert_Generator_ and ends with .zip
current_package = [
    file
    for file in os.listdir()
    if file.startswith("OpenVPN_Cert_Generator_") and file.endswith(".zip")
]

if current_package:
    # Extract the version number from the current package name
    version_number = current_package[0].split("_")[-1].split(".")[0]

    # Increment the version number, assuming it's always formatted as 'vX'
    new_version_number = "v" + str(int(version_number[1:]) + 1)
else:
    # If no current package is found, assume this is the first version
    new_version_number = "v1"

# Define the directory and files to include in the zip archive
dir_to_zip = "needed_binaries"
files_to_zip = [
    "ca_setup.py",
    "client_cert.py",
    "client_manager.py",
    "client_revoke.py",
    "config.py",
    "deploy_ovpn_server_linux.sh",
    "deploy_ovpn_server_on_win10-11.ps1",
    "gen_serv_zip_linux.py",
    "gen_serv_zip_win.py",
    "helpers.py",
    "logger.py",
    "main.py",
    "OpenVPN_Cert_Generator_v1.docx",
    "openvpn_config.py",
    "openvpn_package_generator_windows.py",
    "server_cert.py",
    "start_openvpn.bat",
    "subnet_management.py",
]


# Create the zip archive with the new version number
zip_file_name = f"OpenVPN_Cert_Generator_{new_version_number}.zip"
with zipfile.ZipFile(zip_file_name, "w", zipfile.ZIP_DEFLATED) as zipf:
    # Add files to the zip
    for file in files_to_zip:
        if os.path.isfile(file):  # Check if the file exists
            zipf.write(file)
        else:
            print(f"Warning: {file} not found. Skipping.")

    # Add the directory and its contents, including the directory itself
    if os.path.isdir(dir_to_zip):  # Check if the directory exists
        for root, dirs, files in os.walk(dir_to_zip):
            for file in files:
                full_path = os.path.join(root, file)
                # Ensure the directory structure is preserved in the zip
                zipf.write(
                    full_path, os.path.relpath(full_path, os.path.dirname(dir_to_zip))
                )
    else:
        print(f"Warning: Directory '{dir_to_zip}' not found. Skipping.")

print(f"Created: {zip_file_name}")

# Optionally, remove the old package after verifying the new package is created successfully
if current_package:  # Ensure there is an old package to remove
    if os.path.exists(current_package[0]):
        os.remove(current_package[0])
        print(f"Removed old package: {current_package[0]}")
