#!/bin/bash
set -euo pipefail

###############################################################################
# OpenVPN Server Deployment Script
# Firewall-aware / Multi-distro / Multi-interface aware
# Refactored + CRLF-safe
###############################################################################

###############################################################################
# Ensure system is using systemd
###############################################################################
if [ ! -d /etc/systemd/system ]; then
    echo "This script is only for systemd systems" >&2
    exit 2
fi

###############################################################################
# Ensure script is run as root
###############################################################################
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" >&2
    exit 1
fi

###############################################################################
# Logging helpers
###############################################################################
log() {
    echo "[INFO] $*"
}

warn() {
    echo "[WARN] $*" >&2
}

die() {
    echo "[ERROR] $*" >&2
    exit 1
}

###############################################################################
# Ensure required commands are available
###############################################################################
for cmd in awk grep sed date ip systemctl tr; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        die "Required command missing: $cmd"
    fi
done

###############################################################################
# CRLF cleanup helper
###############################################################################
sanitize_file() {

    local file="$1"

    if [ -f "$file" ]; then
        sed -i 's/\r$//' "$file"
    fi
}

###############################################################################
# Sanitize important files
###############################################################################
sanitize_file "$0"

###############################################################################
# Detect distro and package manager
###############################################################################
if grep -Ei 'debian|ubuntu' /etc/os-release >/dev/null; then

    PKG_MGR="apt"

elif grep -Ei 'fedora|rhel|centos|rocky|alma' /etc/os-release >/dev/null; then

    if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"

    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"

    else
        die "Could not determine package manager."
    fi

    ###########################################################################
    # SELinux handling
    ###########################################################################
    if command -v getenforce >/dev/null 2>&1; then

        log "Setting SELinux to permissive..."

        sed -i 's/^SELINUX=.*/SELINUX=permissive/' \
            /etc/selinux/config || true

        setenforce 0 || true
    fi

else
    die "Unsupported distribution."
fi

###############################################################################
# Install OpenVPN if missing
###############################################################################
if ! command -v openvpn >/dev/null 2>&1; then

    log "Installing OpenVPN..."

    if [ "$PKG_MGR" = "apt" ]; then

        apt update
        apt install -y openvpn

    else

        $PKG_MGR install -y openvpn
    fi
fi

###############################################################################
# Locate server.conf
###############################################################################
if [ -f "./server/server.conf" ]; then

    SERVER_CONF="./server/server.conf"

elif [ -f "/etc/openvpn/server/server.conf" ]; then

    SERVER_CONF="/etc/openvpn/server/server.conf"

else
    die "Could not locate server.conf"
fi

###############################################################################
# Sanitize server.conf
###############################################################################
sanitize_file "$SERVER_CONF"

log "Using server.conf: $SERVER_CONF"

###############################################################################
# Helper to safely parse config values
###############################################################################
get_conf_value() {

    local pattern="$1"

    awk "$pattern" "$SERVER_CONF" | \
        tr -d '\r' | \
        xargs | \
        head -n1
}

###############################################################################
# Parse OpenVPN settings
###############################################################################
OVPN_PORT=$(get_conf_value '/^port / {print $2}')
OVPN_PROTO=$(get_conf_value '/^proto / {print $2}')

OVPN_PORT="${OVPN_PORT:-1194}"
OVPN_PROTO="${OVPN_PROTO:-udp}"

###############################################################################
# Validate protocol
###############################################################################
case "$OVPN_PROTO" in
    udp|tcp)
        ;;
    *)
        die "Invalid OpenVPN protocol detected: '$OVPN_PROTO'"
        ;;
esac

###############################################################################
# Parse OpenVPN VPN subnet
###############################################################################
OVPN_NETWORK=$(get_conf_value '/^server / {print $2}')
OVPN_NETMASK=$(get_conf_value '/^server / {print $3}')

OVPN_NETWORK="${OVPN_NETWORK:-10.0.0.0}"
OVPN_NETMASK="${OVPN_NETMASK:-255.255.255.0}"

###############################################################################
# Convert subnet mask to CIDR
###############################################################################
mask2cidr() {

    local mask=$1
    local IFS=.
    local cidr=0

    for x in $mask; do

        case $x in
            255) ((cidr+=8)) ;;
            254) ((cidr+=7)) ;;
            252) ((cidr+=6)) ;;
            248) ((cidr+=5)) ;;
            240) ((cidr+=4)) ;;
            224) ((cidr+=3)) ;;
            192) ((cidr+=2)) ;;
            128) ((cidr+=1)) ;;
            0) ;;
            *) die "Invalid netmask: $mask" ;;
        esac
    done

    echo "$cidr"
}

OVPN_CIDR=$(mask2cidr "$OVPN_NETMASK")

log "Detected OpenVPN port: $OVPN_PORT/$OVPN_PROTO"
log "Detected VPN subnet: $OVPN_NETWORK/$OVPN_CIDR"

###############################################################################
# Parse server LAN subnet
###############################################################################
LAN_NETWORK=""
LAN_MASK=""

if grep -q "server_local_private_subnet" "$SERVER_CONF"; then

    LAN_NETWORK=$(awk \
        '/server_local_private_subnet/ && $1=="route" {print $2}' \
        "$SERVER_CONF" | tr -d '\r' | head -n1)

    LAN_MASK=$(awk \
        '/server_local_private_subnet/ && $1=="route" {print $3}' \
        "$SERVER_CONF" | tr -d '\r' | head -n1)

    log "Detected LAN subnet: $LAN_NETWORK $LAN_MASK"

else
    warn "No server_local_private_subnet route found."
fi

###############################################################################
# Detect active firewall backend
###############################################################################
FIREWALL="none"

if command -v firewall-cmd >/dev/null 2>&1 && \
   systemctl is-active --quiet firewalld; then

    FIREWALL="firewalld"

elif command -v ufw >/dev/null 2>&1 && \
     ufw status 2>/dev/null | grep -qi "Status: active"; then

    FIREWALL="ufw"

elif command -v nft >/dev/null 2>&1 && \
     [ "$(nft list ruleset 2>/dev/null | wc -l)" -gt 0 ]; then

    FIREWALL="nftables"

elif command -v iptables >/dev/null 2>&1; then

    FIREWALL="iptables"
fi

log "Detected firewall backend: $FIREWALL"

###############################################################################
# Detect WAN interface
###############################################################################
WAN_IF=$(ip route show default | awk '/default/ {print $5}' | head -n1)

if [ -z "$WAN_IF" ]; then
    die "Could not determine WAN interface."
fi

log "Detected WAN interface: $WAN_IF"

###############################################################################
# Helper: IP to integer
###############################################################################
ip_to_int() {

    local a b c d

    IFS=. read -r a b c d <<< "$1"

    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

###############################################################################
# Helper: Check if IP belongs to subnet
###############################################################################
ip_in_subnet() {

    local ip="$1"
    local network="$2"
    local mask="$3"

    local ip_int
    local net_int
    local mask_int

    ip_int=$(ip_to_int "$ip")
    net_int=$(ip_to_int "$network")
    mask_int=$(ip_to_int "$mask")

    [ $((ip_int & mask_int)) -eq $((net_int & mask_int)) ]
}

###############################################################################
# Detect LAN interface
###############################################################################
LAN_IF=""

if [ -n "$LAN_NETWORK" ] && [ -n "$LAN_MASK" ]; then

    for iface in $(ip -o -4 addr show | awk '{print $2}' | sort -u); do

        [ "$iface" = "lo" ] && continue
        [ "$iface" = "$WAN_IF" ] && continue

        iface_ip=$(ip -o -4 addr show "$iface" | \
            awk '{print $4}' | cut -d/ -f1 | head -n1)

        if [ -n "$iface_ip" ]; then

            if ip_in_subnet "$iface_ip" "$LAN_NETWORK" "$LAN_MASK"; then

                LAN_IF="$iface"
                break
            fi
        fi
    done
fi

if [ -n "$LAN_IF" ]; then
    log "Detected LAN interface: $LAN_IF"
else
    warn "No separate LAN interface detected."
fi

###############################################################################
# Configure firewall
###############################################################################
case "$FIREWALL" in

###############################################################################
# FIREWALLD
###############################################################################
firewalld)

    log "Configuring firewalld..."

    firewall-cmd --permanent --zone=external \
        --add-interface="$WAN_IF" || true

    firewall-cmd --permanent --zone=external \
        --add-port="${OVPN_PORT}/${OVPN_PROTO}"

    firewall-cmd --permanent --zone=external \
        --add-port=7505/tcp

    firewall-cmd --permanent --zone=external \
        --add-masquerade

    if [ -n "$LAN_IF" ]; then

        firewall-cmd --permanent --zone=internal \
            --add-interface="$LAN_IF" || true
    fi

    firewall-cmd --permanent --zone=internal \
        --add-interface=tun0 || true

    firewall-cmd --reload
    ;;

###############################################################################
# UFW
###############################################################################
ufw)

    log "Configuring UFW..."

    ufw allow in on "$WAN_IF" \
        to any port "$OVPN_PORT" proto "$OVPN_PROTO"

    ufw allow in on "$WAN_IF" \
        to any port 7505 proto tcp

    if [ -n "$LAN_IF" ]; then

        ufw allow in on "$LAN_IF" \
            to any port 7505 proto tcp
    fi

    ufw allow in on tun0 \
        to any port 7505 proto tcp
    ;;

###############################################################################
# NFTABLES
###############################################################################
nftables)

    log "Configuring nftables..."

    nft list table inet ovpn_fw >/dev/null 2>&1 || \
        nft add table inet ovpn_fw

    nft list chain inet ovpn_fw input >/dev/null 2>&1 || \
        nft add chain inet ovpn_fw input \
        '{ type filter hook input priority 0; policy accept; }'

    nft add rule inet ovpn_fw input \
        iifname "$WAN_IF" \
        "$OVPN_PROTO" dport "$OVPN_PORT" accept \
        2>/dev/null || true

    nft add rule inet ovpn_fw input \
        tcp dport 7505 accept \
        2>/dev/null || true
    ;;

###############################################################################
# IPTABLES
###############################################################################
iptables)

    log "Configuring iptables..."

    iptables -C INPUT \
        -p "$OVPN_PROTO" \
        --dport "$OVPN_PORT" \
        -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 \
        -p "$OVPN_PROTO" \
        --dport "$OVPN_PORT" \
        -j ACCEPT

    iptables -C INPUT \
        -p tcp \
        --dport 7505 \
        -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 \
        -p tcp \
        --dport 7505 \
        -j ACCEPT

    iptables -C INPUT \
        -i tun0 \
        -p tcp \
        --dport 7505 \
        -j ACCEPT 2>/dev/null || \
    iptables -I INPUT 1 \
        -i tun0 \
        -p tcp \
        --dport 7505 \
        -j ACCEPT

    if [ -n "$LAN_IF" ]; then

        iptables -C INPUT \
            -i "$LAN_IF" \
            -p tcp \
            --dport 7505 \
            -j ACCEPT 2>/dev/null || \
        iptables -I INPUT 1 \
            -i "$LAN_IF" \
            -p tcp \
            --dport 7505 \
            -j ACCEPT
    fi

    iptables -C FORWARD \
        -i tun0 \
        -m state --state NEW,RELATED,ESTABLISHED \
        -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 \
        -i tun0 \
        -m state --state NEW,RELATED,ESTABLISHED \
        -j ACCEPT

    iptables -C FORWARD \
        -o tun0 \
        -m state --state RELATED,ESTABLISHED \
        -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 \
        -o tun0 \
        -m state --state RELATED,ESTABLISHED \
        -j ACCEPT

    iptables -t nat -C POSTROUTING \
        -s "${OVPN_NETWORK}/${OVPN_CIDR}" \
        -o "$WAN_IF" \
        -j MASQUERADE 2>/dev/null || \
    iptables -t nat -I POSTROUTING 1 \
        -s "${OVPN_NETWORK}/${OVPN_CIDR}" \
        -o "$WAN_IF" \
        -j MASQUERADE
    ;;

###############################################################################
# NO FIREWALL
###############################################################################
none)

    warn "No firewall backend detected."
    ;;

esac

###############################################################################
# Persist iptables rules
###############################################################################
if [ "$FIREWALL" = "iptables" ]; then

    if [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then

        if ! rpm -q iptables-services >/dev/null 2>&1; then
            $PKG_MGR install -y iptables-services
        fi

        service iptables save || true
        systemctl enable iptables || true

    elif [ "$PKG_MGR" = "apt" ]; then

        export DEBIAN_FRONTEND=noninteractive

        apt install -y iptables-persistent || true
        netfilter-persistent save || true
    fi
fi

###############################################################################
# Ensure OpenVPN directory exists
###############################################################################
mkdir -p /etc/openvpn/server

###############################################################################
# Backup existing config
###############################################################################
BACKUP_DIR="/etc/openvpn/server/backup_$(date +%F_%H-%M-%S)"

mkdir -p "$BACKUP_DIR"

for i in ccd ipp.txt server.conf openvpn.log openvpn-status.log; do

    if [ -e /etc/openvpn/server/$i ]; then
        mv /etc/openvpn/server/$i "$BACKUP_DIR"
    fi
done

###############################################################################
# Deploy OpenVPN files
###############################################################################
log "Deploying OpenVPN configuration..."

cp -r ./server/* /etc/openvpn/server/

###############################################################################
# Ensure CCD directory exists
###############################################################################
mkdir -p /etc/openvpn/server/ccd

###############################################################################
# Ensure runtime files exist
###############################################################################
touch /etc/openvpn/server/ipp.txt
touch /etc/openvpn/server/openvpn.log
touch /etc/openvpn/server/openvpn-status.log

###############################################################################
# Enable IPv4 forwarding
###############################################################################
log "Enabling IPv4 forwarding..."

sysctl -w net.ipv4.ip_forward=1

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    die "IPv4 forwarding failed to enable."
fi

if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi

###############################################################################
# Stop existing service
###############################################################################
if systemctl is-active --quiet openvpn-server@server.service; then

    log "Stopping existing OpenVPN service..."

    systemctl stop openvpn-server@server.service
fi

###############################################################################
# Enable OpenVPN service
###############################################################################
systemctl enable openvpn-server@server.service

###############################################################################
# Start OpenVPN
###############################################################################
log "Starting OpenVPN..."

systemctl restart openvpn-server@server.service

sleep 3

###############################################################################
# Verify service
###############################################################################
if systemctl is-active --quiet openvpn-server@server.service; then

    log "OpenVPN started successfully."

else

    journalctl -u openvpn-server@server.service \
        -n 50 \
        --no-pager

    die "OpenVPN failed to start."
fi

###############################################################################
# Final summary
###############################################################################
echo
echo "=================================================="
echo " OpenVPN Deployment Summary"
echo "=================================================="
echo " Firewall Backend : $FIREWALL"
echo " WAN Interface    : $WAN_IF"
echo " LAN Interface    : ${LAN_IF:-none}"
echo " OpenVPN Port     : $OVPN_PORT/$OVPN_PROTO"
echo " VPN Subnet       : ${OVPN_NETWORK}/${OVPN_CIDR}"
echo " Management Port  : 7505/tcp"
echo "=================================================="
echo