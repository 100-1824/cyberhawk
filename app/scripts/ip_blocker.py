#!/usr/bin/env python3
"""
IP Blocker Script for CyberHawk
Blocks malicious IPs without using Windows Firewall

Methods used:
1. Null Route: Adds route to 0.0.0.0 (blackhole) for the IP
2. Hosts File: Adds entry redirecting IP to localhost (127.0.0.1)

Requires Administrator privileges to run.
"""

import sys
import os
import subprocess
import json
import argparse
from datetime import datetime

# Configuration
PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BLOCKED_IPS_FILE = os.path.join(PROJECT_DIR, 'assets', 'data', 'blocked_ips_system.json')
HOSTS_FILE = r'C:\Windows\System32\drivers\etc\hosts'

def is_admin():
    """Check if script is running with administrator privileges"""
    try:
        return os.getuid() == 0
    except AttributeError:
        # Windows
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def load_blocked_ips():
    """Load the list of blocked IPs from JSON file"""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_blocked_ips(blocked_list):
    """Save the list of blocked IPs to JSON file"""
    os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(blocked_list, f, indent=2)

def add_null_route(ip):
    """
    Add a null route for the IP (send packets to nowhere)
    This effectively blocks all traffic to/from this IP
    """
    try:
        # Add route to null (0.0.0.0) - this drops all packets
        result = subprocess.run(
            ['route', 'add', ip, 'mask', '255.255.255.255', '0.0.0.0', 'metric', '1'],
            capture_output=True,
            text=True,
            shell=True
        )
        if result.returncode == 0:
            return True, "Null route added successfully"
        else:
            # Try alternative: route to localhost
            result2 = subprocess.run(
                ['route', 'add', ip, '127.0.0.1', 'metric', '1'],
                capture_output=True,
                text=True,
                shell=True
            )
            return result2.returncode == 0, result2.stdout or result2.stderr
    except Exception as e:
        return False, str(e)

def remove_null_route(ip):
    """Remove the null route for the IP"""
    try:
        result = subprocess.run(
            ['route', 'delete', ip],
            capture_output=True,
            text=True,
            shell=True
        )
        return result.returncode == 0, result.stdout or result.stderr
    except Exception as e:
        return False, str(e)

def add_to_hosts_file(ip):
    """
    Add IP to hosts file, redirecting to localhost
    This blocks any DNS-based access to services on that IP
    """
    try:
        # Check if already in hosts file
        with open(HOSTS_FILE, 'r') as f:
            content = f.read()
        
        block_marker = f"# CYBERHAWK_BLOCKED: {ip}"
        if block_marker in content:
            return True, "Already in hosts file"
        
        # Add to hosts file
        with open(HOSTS_FILE, 'a') as f:
            f.write(f"\n127.0.0.1\t{ip}\t{block_marker}\n")
        
        return True, "Added to hosts file"
    except PermissionError:
        return False, "Permission denied - run as administrator"
    except Exception as e:
        return False, str(e)

def remove_from_hosts_file(ip):
    """Remove IP from hosts file"""
    try:
        with open(HOSTS_FILE, 'r') as f:
            lines = f.readlines()
        
        block_marker = f"# CYBERHAWK_BLOCKED: {ip}"
        new_lines = [line for line in lines if block_marker not in line]
        
        with open(HOSTS_FILE, 'w') as f:
            f.writelines(new_lines)
        
        return True, "Removed from hosts file"
    except PermissionError:
        return False, "Permission denied - run as administrator"
    except Exception as e:
        return False, str(e)

def block_ip(ip, reason="User blocked"):
    """Block an IP address using all available methods"""
    results = {
        'ip': ip,
        'success': False,
        'methods': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # Validate IP format
    parts = ip.split('.')
    if len(parts) != 4:
        results['error'] = "Invalid IP format"
        return results
    
    try:
        for part in parts:
            if not 0 <= int(part) <= 255:
                results['error'] = "Invalid IP range"
                return results
    except ValueError:
        results['error'] = "Invalid IP format"
        return results
    
    # Skip blocking localhost and private network ranges (optional)
    if ip.startswith('127.') or ip == '0.0.0.0':
        results['error'] = "Cannot block localhost"
        return results
    
    # Method 1: Add null route
    route_success, route_msg = add_null_route(ip)
    results['methods']['null_route'] = {
        'success': route_success,
        'message': route_msg
    }
    
    # Method 2: Add to hosts file
    hosts_success, hosts_msg = add_to_hosts_file(ip)
    results['methods']['hosts_file'] = {
        'success': hosts_success,
        'message': hosts_msg
    }
    
    # Consider successful if at least one method worked
    results['success'] = route_success or hosts_success
    
    # Save to blocked IPs list
    if results['success']:
        blocked_list = load_blocked_ips()
        # Check if already blocked
        if not any(b['ip'] == ip for b in blocked_list):
            blocked_list.append({
                'ip': ip,
                'blocked_at': results['timestamp'],
                'reason': reason,
                'methods_used': [m for m, r in results['methods'].items() if r['success']]
            })
            save_blocked_ips(blocked_list)
    
    return results

def unblock_ip(ip):
    """Unblock an IP address"""
    results = {
        'ip': ip,
        'success': False,
        'methods': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # Method 1: Remove null route
    route_success, route_msg = remove_null_route(ip)
    results['methods']['null_route'] = {
        'success': route_success,
        'message': route_msg
    }
    
    # Method 2: Remove from hosts file
    hosts_success, hosts_msg = remove_from_hosts_file(ip)
    results['methods']['hosts_file'] = {
        'success': hosts_success,
        'message': hosts_msg
    }
    
    results['success'] = True  # Unblock is considered successful even if IP wasn't blocked
    
    # Remove from blocked IPs list
    blocked_list = load_blocked_ips()
    blocked_list = [b for b in blocked_list if b['ip'] != ip]
    save_blocked_ips(blocked_list)
    
    return results

def list_blocked_ips():
    """List all currently blocked IPs"""
    return load_blocked_ips()

def check_ip_blocked(ip):
    """Check if an IP is currently blocked"""
    blocked_list = load_blocked_ips()
    for blocked in blocked_list:
        if blocked['ip'] == ip:
            return {'blocked': True, 'details': blocked}
    return {'blocked': False}

def main():
    parser = argparse.ArgumentParser(description='CyberHawk IP Blocker')
    parser.add_argument('action', choices=['block', 'unblock', 'list', 'check'],
                       help='Action to perform')
    parser.add_argument('--ip', help='IP address to block/unblock/check')
    parser.add_argument('--reason', default='User blocked',
                       help='Reason for blocking')
    parser.add_argument('--json', action='store_true',
                       help='Output in JSON format')
    
    args = parser.parse_args()
    
    if args.action in ['block', 'unblock', 'check'] and not args.ip:
        print(json.dumps({'error': 'IP address is required for this action'}))
        sys.exit(1)
    
    if args.action == 'block':
        result = block_ip(args.ip, args.reason)
    elif args.action == 'unblock':
        result = unblock_ip(args.ip)
    elif args.action == 'list':
        result = {'blocked_ips': list_blocked_ips()}
    elif args.action == 'check':
        result = check_ip_blocked(args.ip)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if args.action == 'block':
            if result['success']:
                print(f"Successfully blocked IP: {args.ip}")
                for method, details in result['methods'].items():
                    status = "OK" if details['success'] else "FAIL"
                    print(f"   {status} {method}: {details['message']}")
            else:
                print(f"Failed to block IP: {args.ip}")
                print(f"   Error: {result.get('error', 'Unknown error')}")
        elif args.action == 'unblock':
            if result['success']:
                print(f"Successfully unblocked IP: {args.ip}")
            else:
                print(f"Failed to unblock IP: {args.ip}")
        elif args.action == 'list':
            blocked = result['blocked_ips']
            if blocked:
                print(f"Currently blocked IPs ({len(blocked)}):")
                for b in blocked:
                    print(f"   - {b['ip']} - blocked at {b['blocked_at']} ({b['reason']})")
            else:
                print("No IPs currently blocked")
        elif args.action == 'check':
            if result['blocked']:
                print(f"IP {args.ip} is BLOCKED")
                print(f"   Blocked at: {result['details']['blocked_at']}")
                print(f"   Reason: {result['details']['reason']}")
            else:
                print(f"IP {args.ip} is NOT blocked")

if __name__ == '__main__':
    main()
