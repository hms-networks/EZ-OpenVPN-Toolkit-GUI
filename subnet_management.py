# Copyright (C) 2024 - 2025 HMS Industrial Network Solutions
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# subnet_management.py

import ipaddress
import logging
import csv
import os
from helpers import get_base_dir

BASE_DIR = get_base_dir()


def validate_subnet(subnet_input, existing_subnets=None):
    """
    Validates the subnet input, checks for overlaps, and returns an ipaddress.IPv4Network object.
    Accepts both CIDR notation and dotted decimal netmask notation.
    """
    if existing_subnets is None:
        existing_subnets = []
    try:
        subnet_input = subnet_input.strip()
        # Check if the input is in 'address netmask' format
        if " " in subnet_input:
            address, netmask = subnet_input.split()
            # Convert netmask to prefix length
            try:
                netmask_ip = ipaddress.IPv4Address(netmask)
                # Convert netmask to integer prefix length
                netmask_bits = bin(int(netmask_ip)).count("1")
                subnet_cidr = f"{address}/{netmask_bits}"
            except ipaddress.AddressValueError:
                raise ValueError(f"Invalid netmask: {netmask}")
        else:
            subnet_cidr = subnet_input

        subnet = ipaddress.ip_network(subnet_cidr, strict=False)

        for existing in existing_subnets:
            existing_subnet = ipaddress.ip_network(existing, strict=False)
            if subnet.overlaps(existing_subnet):
                raise ValueError(
                    f"Subnet {subnet} overlaps with existing subnet {existing_subnet}"
                )
        logging.info(f"Validated subnet: {subnet}")
        return subnet
    except ValueError as e:
        logging.error(f"Invalid subnet: {e}")
        raise


def load_existing_subnets(subnets_csv):
    """Loads existing subnets from a CSV file."""
    subnets = []
    if os.path.exists(subnets_csv):
        with open(subnets_csv, "r", newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                subnets.append(row["Subnet"])
    return subnets


def save_subnet_to_csv(subnets_csv, client_name, subnet):
    """Saves the client name and subnet to a CSV file."""
    file_exists = os.path.isfile(subnets_csv)
    with open(subnets_csv, "a", newline="") as f:
        fieldnames = ["Name", "Subnet"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerow({"Name": client_name, "Subnet": str(subnet)})
    logging.info(f"Saved subnet for {client_name} to CSV: {subnet}")


def remove_client_from_csv(subnets_csv, client_name):
    """Removes a client's subnet from subnets.csv."""
    if os.path.exists(subnets_csv):
        with open(subnets_csv, "r", newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            rows = [row for row in reader if row["Name"] != client_name]
        with open(subnets_csv, "w", newline="") as csvfile:
            fieldnames = ["Name", "Subnet"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logging.info(f"Removed subnet for client {client_name} from CSV")


def get_subnet_by_name(subnets_csv, name):
    """Retrieves a subnet from subnets.csv by its name."""
    if os.path.exists(subnets_csv):
        with open(subnets_csv, "r", newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if row["Name"] == name:
                    return ipaddress.ip_network(row["Subnet"])
    return None


def get_client_subnets(subnets_csv):
    """
    Retrieves all client subnets from subnets.csv except for 'openvpn_tunnel_subnet' and 'server_local_private_subnet'.
    Returns a dictionary with client names as keys and ipaddress.IPv4Network objects as values.
    """
    client_subnets = {}
    if os.path.exists(subnets_csv):
        with open(subnets_csv, "r", newline="") as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                name = row["Name"]
                if name not in ["openvpn_tunnel_subnet", "server_local_private_subnet"]:
                    subnet = ipaddress.ip_network(row["Subnet"])
                    client_subnets[name] = subnet
    return client_subnets
