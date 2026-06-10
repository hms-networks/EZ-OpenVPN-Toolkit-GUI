#!/usr/bin/env python3
"""
OpenVPN Server Deployment Script for Linux
Deploys the initialized OpenVPN server to systemd
"""

import os
import sys
import subprocess
import shutil
import logging
from datetime import datetime

def get_base_dir():
    """Get the base directory of the toolkit"""
    return os.path.dirname(os.path.abspath(__file__))

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        print("❌ This script must be run as root (sudo)")
        print("   Run: sudo python deploy_server.py")
        return False
    return True

def check_openvpn_installed():
    """Check if OpenVPN is installed"""
    if shutil.which('openvpn') is None:
        print("❌ OpenVPN is not installed")
        print("\nInstall it with:")
        print("  Ubuntu/Debian: sudo apt-get install openvpn")
        print("  Fedora/RHEL:   sudo dnf install openvpn")
        return False
    return True

def check_firewalld():
    """Check if firewalld is installed and running"""
    if shutil.which('firewall-cmd') is None:
        print("⚠️  firewalld is not installed")
        print("   Installing firewalld...")
        try:
            # Detect package manager
            if shutil.which('apt-get'):
                subprocess.run(['apt-get', 'update'], check=True)
                subprocess.run(['apt-get', 'install', '-y', 'firewalld'], check=True)
            elif shutil.which('dnf'):
                subprocess.run(['dnf', 'install', '-y', 'firewalld'], check=True)
            elif shutil.which('yum'):
                subprocess.run(['yum', 'install', '-y', 'firewalld'], check=True)
        except subprocess.CalledProcessError:
            print("❌ Failed to install firewalld")
            return False
    
    # Start and enable firewalld
    try:
        subprocess.run(['systemctl', 'enable', 'firewalld'], check=True, capture_output=True)
        subprocess.run(['systemctl', 'start', 'firewalld'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("⚠️  Could not start firewalld, continuing anyway...")
    
    return True

def stop_existing_service():
    """Stop any existing OpenVPN server service"""
    try:
        # Check if service is active
        result = subprocess.run(
            ['systemctl', 'is-active', 'openvpn-server@server.service'],
            capture_output=True,
            text=True
        )
        
        if result.stdout.strip() == 'active':
            print("🔄 Stopping existing OpenVPN service...")
            subprocess.run(['systemctl', 'stop', 'openvpn-server@server.service'], check=True)
            subprocess.run(['systemctl', 'disable', 'openvpn-server@server.service'], check=True)
            print("✅ Stopped existing service")
    except subprocess.CalledProcessError:
        pass  # Service doesn't exist, that's fine

def backup_existing_config():
    """Backup existing configuration if present"""
    server_conf = '/etc/openvpn/server/server.conf'
    if os.path.exists(server_conf):
        backup_dir = f'/etc/openvpn/server/backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
        print(f"📦 Backing up existing config to {backup_dir}")
        os.makedirs(backup_dir, exist_ok=True)
        
        for item in ['ccd', 'ipp.txt', 'server.conf', 'openvpn.log', 'openvpn-status.log']:
            src = f'/etc/openvpn/server/{item}'
            if os.path.exists(src):
                if os.path.isdir(src):
                    shutil.copytree(src, f'{backup_dir}/{item}')
                else:
                    shutil.copy2(src, backup_dir)

def deploy_server_config(base_dir):
    """Deploy server configuration files"""
    server_dir = os.path.join(base_dir, 'server')
    server_conf = os.path.join(server_dir, 'server.conf')
    
    if not os.path.exists(server_conf):
        print("❌ Server not initialized. Run initialization first.")
        return False
    
    print("📋 Deploying server configuration...")
    
    # Create OpenVPN server directory
    os.makedirs('/etc/openvpn/server', exist_ok=True)
    
    # Copy server.conf
    shutil.copy2(server_conf, '/etc/openvpn/server/server.conf')
    print("   ✅ Copied server.conf")
    
    # Copy CCD directory
    ccd_src = os.path.join(server_dir, 'ccd')
    ccd_dst = '/etc/openvpn/server/ccd'
    if os.path.exists(ccd_src):
        if os.path.exists(ccd_dst):
            shutil.rmtree(ccd_dst)
        shutil.copytree(ccd_src, ccd_dst)
        print("   ✅ Copied client configs (ccd)")
    else:
        os.makedirs(ccd_dst, exist_ok=True)
    
    # Create/touch log files
    for logfile in ['ipp.txt', 'openvpn.log', 'openvpn-status.log']:
        open(f'/etc/openvpn/server/{logfile}', 'a').close()
    
    print("✅ Configuration deployed")
    return True

def configure_firewall(server_conf_path):
    """Configure firewall to allow OpenVPN traffic"""
    # Extract port and protocol from server.conf
    port = '1194'
    proto = 'udp'
    
    try:
        with open(server_conf_path, 'r') as f:
            for line in f:
                if line.strip().startswith('port '):
                    port = line.split()[1]
                elif line.strip().startswith('proto '):
                    proto = line.split()[1]
    except Exception as e:
        print(f"⚠️  Could not read port/protocol from config, using defaults: {e}")
    
    print(f"🔥 Configuring firewall for {proto}/{port}...")
    
    try:
        # Add firewall rule
        subprocess.run(
            ['firewall-cmd', f'--add-port={port}/{proto}', '--permanent'],
            check=True,
            capture_output=True
        )
        subprocess.run(['firewall-cmd', '--reload'], check=True, capture_output=True)
        print(f"✅ Firewall configured to allow {proto}/{port}")
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Could not configure firewall: {e}")
        print(f"   You may need to manually allow port {port}/{proto}")
    except FileNotFoundError:
        print("⚠️  firewalld not available, skipping firewall configuration")

def enable_ip_forwarding():
    """Enable IP forwarding for routing"""
    print("🔀 Enabling IP forwarding...")
    
    # Enable immediately
    try:
        subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], check=True, capture_output=True)
        print("   ✅ IP forwarding enabled")
    except subprocess.CalledProcessError:
        print("   ⚠️  Could not enable IP forwarding")
    
    # Make persistent
    sysctl_conf = '/etc/sysctl.d/99-openvpn.conf'
    with open(sysctl_conf, 'w') as f:
        f.write("# Enable IP forwarding for OpenVPN\n")
        f.write("net.ipv4.ip_forward = 1\n")
    print("   ✅ IP forwarding will persist after reboot")

def configure_selinux():
    """Set SELinux to permissive for OpenVPN if needed"""
    if not os.path.exists('/etc/selinux/config'):
        return  # SELinux not present
    
    print("🔒 Configuring SELinux...")
    try:
        # Check current mode
        result = subprocess.run(['getenforce'], capture_output=True, text=True)
        if 'Enforcing' in result.stdout:
            print("   Setting SELinux to permissive mode for OpenVPN...")
            subprocess.run(['setenforce', '0'], check=True)
            
            # Update config file
            with open('/etc/selinux/config', 'r') as f:
                lines = f.readlines()
            
            with open('/etc/selinux/config', 'w') as f:
                for line in lines:
                    if line.startswith('SELINUX='):
                        f.write('SELINUX=permissive\n')
                    else:
                        f.write(line)
            
            print("   ✅ SELinux set to permissive")
    except Exception as e:
        print(f"   ⚠️  Could not configure SELinux: {e}")

def start_openvpn_service():
    """Start and enable OpenVPN service"""
    print("🚀 Starting OpenVPN service...")
    
    try:
        subprocess.run(['systemctl', 'enable', 'openvpn-server@server.service'], check=True)
        subprocess.run(['systemctl', 'start', 'openvpn-server@server.service'], check=True)
        print("✅ OpenVPN service started and enabled")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start OpenVPN service: {e}")
        return False

def check_service_status():
    """Check if OpenVPN service is running"""
    try:
        result = subprocess.run(
            ['systemctl', 'is-active', 'openvpn-server@server.service'],
            capture_output=True,
            text=True
        )
        
        if result.stdout.strip() == 'active':
            print("\n✅ OpenVPN server is running!")
            
            # Show status
            subprocess.run(['systemctl', 'status', 'openvpn-server@server.service', '--no-pager', '-l'])
            return True
        else:
            print("\n❌ OpenVPN server is not running")
            print("\nCheck logs with:")
            print("  sudo journalctl -u openvpn-server@server.service -n 50")
            return False
    except subprocess.CalledProcessError:
        return False

def show_connection_info(base_dir):
    """Show connection information"""
    import json
    
    details_file = os.path.join(base_dir, 'server_details.json')
    if os.path.exists(details_file):
        with open(details_file, 'r') as f:
            details = json.load(f)
        
        print("\n" + "="*60)
        print("📡 OpenVPN Server Information")
        print("="*60)
        print(f"Server Address: {details.get('server_address', 'N/A')}")
        print(f"Port:           {details.get('port', 'N/A')}")
        print(f"Protocol:       {details.get('proto', 'N/A').upper()}")
        print("="*60)
        print("\nClients can now connect using their .ovpn configuration files!")
        print("\nUseful commands:")
        print("  Status:  sudo systemctl status openvpn-server@server")
        print("  Stop:    sudo systemctl stop openvpn-server@server")
        print("  Restart: sudo systemctl restart openvpn-server@server")
        print("  Logs:    sudo journalctl -u openvpn-server@server -f")
        print("="*60 + "\n")

def main():
    print("\n" + "="*60)
    print("OpenVPN Server Deployment Script")
    print("="*60 + "\n")
    
    base_dir = get_base_dir()
    
    # Pre-flight checks
    if not check_root():
        sys.exit(1)
    
    if not check_openvpn_installed():
        sys.exit(1)
    
    # Deployment steps
    check_firewalld()
    stop_existing_service()
    backup_existing_config()
    
    if not deploy_server_config(base_dir):
        sys.exit(1)
    
    configure_firewall('/etc/openvpn/server/server.conf')
    enable_ip_forwarding()
    configure_selinux()
    
    if start_openvpn_service():
        import time
        time.sleep(2)  # Give it a moment to start
        
        if check_service_status():
            show_connection_info(base_dir)
            print("✅ Deployment complete!")
            sys.exit(0)
        else:
            print("\n⚠️  Service started but may have issues. Check logs above.")
            sys.exit(1)
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
