"""
Cyber_NetCAT — Network Reconnaissance Module

Host discovery via ping sweep, ARP scanning, traceroute,
OS fingerprinting via TTL analysis, and network interface enumeration.
"""

import os
import re
import socket
import struct
import subprocess
import time
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold, progress_bar
)
from netcat_tool.utils.banner import print_module_banner


# TTL-based OS fingerprinting reference
TTL_OS_MAP = {
    (0, 32): 'Unknown (very low TTL)',
    (32, 64): 'Linux/Unix (TTL ~64)',
    (64, 65): 'Linux/Unix/macOS',
    (65, 128): 'Windows (TTL ~128)',
    (128, 129): 'Windows',
    (129, 255): 'Network Device / Solaris / AIX (TTL ~255)',
    (255, 256): 'Network Device / Solaris / AIX',
}


def _guess_os_from_ttl(ttl):
    """Guess the OS based on TTL value."""
    for (low, high), os_name in TTL_OS_MAP.items():
        if low <= ttl < high:
            return os_name
    return "Unknown"


def _ping_host(ip, timeout=1):
    """
    Ping a single host to check if it's alive.

    Args:
        ip: IP address to ping.
        timeout: Ping timeout in seconds.

    Returns:
        Dictionary with ip, alive status, ttl, and latency.
    """
    result = {'ip': str(ip), 'alive': False, 'ttl': None, 'latency': None, 'os_guess': None}

    param = '-n' if platform.system().lower() == 'windows' else '-c'
    timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'
    timeout_val = str(int(timeout * 1000)) if platform.system().lower() == 'windows' else str(timeout)

    try:
        start = time.time()
        output = subprocess.run(
            ['ping', param, '1', timeout_param, timeout_val, str(ip)],
            capture_output=True, text=True, timeout=timeout + 2
        )
        latency = round((time.time() - start) * 1000, 1)

        if output.returncode == 0:
            result['alive'] = True
            result['latency'] = latency

            # Extract TTL from output
            ttl_match = re.search(r'[Tt][Tt][Ll][=: ](\d+)', output.stdout)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                result['ttl'] = ttl
                result['os_guess'] = _guess_os_from_ttl(ttl)

    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass

    return result


def _ping_sweep(cidr, threads=50, timeout=1):
    """
    Perform a ping sweep over a CIDR range.

    Args:
        cidr: CIDR network string (e.g., '192.168.1.0/24').
        threads: Number of concurrent threads.
        timeout: Ping timeout per host.

    Returns:
        List of results for alive hosts.
    """
    network = ip_network(cidr, strict=False)
    hosts = list(network.hosts())
    total = len(hosts)

    print_info(f"Sweeping {total} hosts in {cidr}")
    print()

    alive_hosts = []
    checked = 0

    def check_host(ip):
        nonlocal checked
        result = _ping_host(ip, timeout)
        checked += 1
        progress_bar(checked, total, prefix="Sweeping")
        return result

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_host, host): host for host in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result['alive']:
                alive_hosts.append(result)

    print()  # newline after progress bar
    return alive_hosts


def _traceroute(target, max_hops=30, timeout=2):
    """
    Perform a traceroute to the target.

    Args:
        target: Target IP or hostname.
        max_hops: Maximum number of hops.
        timeout: Timeout per hop.

    Returns:
        List of hop dictionaries.
    """
    hops = []
    is_windows = platform.system().lower() == 'windows'

    try:
        if is_windows:
            cmd = ['tracert', '-d', '-w', str(int(timeout * 1000)), '-h', str(max_hops), target]
        else:
            cmd = ['traceroute', '-n', '-w', str(timeout), '-m', str(max_hops), target]

        print_info(f"Tracing route to {target} (max {max_hops} hops)...")
        print()

        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops * timeout + 10)
        output = proc.stdout

        # Parse output
        hop_num = 0
        for line in output.splitlines():
            # Match traceroute output patterns
            # Windows: "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
            # Linux:   " 1  192.168.1.1  0.891 ms  0.456 ms  0.345 ms"

            if is_windows:
                match = re.match(
                    r'\s*(\d+)\s+(?:(<?\d+)\s*ms\s+)?(?:(<?\d+)\s*ms\s+)?(?:(<?\d+)\s*ms\s+)?(\S+)?',
                    line
                )
            else:
                match = re.match(
                    r'\s*(\d+)\s+(\S+)\s+(\S+)\s*ms',
                    line
                )

            if match:
                hop_num += 1
                groups = match.groups()

                if is_windows:
                    hop_ip = groups[4] if groups[4] and groups[4] != '*' else '*'
                    latencies = [g for g in groups[1:4] if g]
                    avg_latency = None
                    if latencies:
                        nums = []
                        for l in latencies:
                            l = l.replace('<', '')
                            try:
                                nums.append(float(l))
                            except ValueError:
                                pass
                        if nums:
                            avg_latency = round(sum(nums) / len(nums), 1)
                else:
                    hop_ip = groups[1] if groups[1] != '*' else '*'
                    try:
                        avg_latency = float(groups[2])
                    except (ValueError, IndexError):
                        avg_latency = None

                # Reverse DNS
                hostname = None
                if hop_ip != '*':
                    try:
                        hostname, _, _ = socket.gethostbyaddr(hop_ip)
                    except (socket.herror, socket.gaierror):
                        pass

                hop = {
                    'hop': hop_num,
                    'ip': hop_ip,
                    'hostname': hostname,
                    'latency_ms': avg_latency,
                }
                hops.append(hop)

                # Display
                lat_str = f"{avg_latency} ms" if avg_latency else "*"
                host_str = f" ({hostname})" if hostname else ""
                if hop_ip == '*':
                    print(f"    {dim(str(hop_num) + '.'):<6} {warning('*  Request timed out')}")
                else:
                    print(f"    {bold(str(hop_num) + '.'):<6} {hop_ip:<18} {dim(lat_str):<12}{dim(host_str)}")

    except subprocess.TimeoutExpired:
        print_warning("Traceroute timed out")
    except FileNotFoundError:
        print_error("Traceroute command not found. Install traceroute/tracert.")
    except Exception as e:
        print_error(f"Traceroute error: {e}")

    return hops


def _os_detect(target, timeout=2):
    """
    Detect OS of target via TTL analysis and port probing.

    Args:
        target: Target IP or hostname.
        timeout: Connection timeout.

    Returns:
        Dictionary with OS detection results.
    """
    result = {'target': target, 'ttl': None, 'os_guess': None, 'details': []}

    # Ping for TTL
    try:
        ip = socket.gethostbyname(target)
        ping_result = _ping_host(ip, timeout)

        if ping_result['alive']:
            result['ttl'] = ping_result['ttl']
            result['os_guess'] = ping_result['os_guess']
            result['latency'] = ping_result['latency']

            # Additional checks via open ports
            os_hints = []

            # Check common OS-specific ports
            test_ports = {
                22: 'SSH (Linux/Unix)',
                135: 'MSRPC (Windows)',
                139: 'NetBIOS (Windows)',
                445: 'SMB (Windows)',
                548: 'AFP (macOS)',
                3389: 'RDP (Windows)',
                5900: 'VNC (Various)',
            }

            for port, desc in test_ports.items():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    if sock.connect_ex((ip, port)) == 0:
                        os_hints.append(desc)
                    sock.close()
                except socket.error:
                    pass

            result['details'] = os_hints
        else:
            result['os_guess'] = 'Host appears to be down'

    except socket.gaierror:
        result['os_guess'] = f'Cannot resolve: {target}'

    return result


def _list_interfaces():
    """
    List local network interfaces and their IP addresses.

    Returns:
        List of interface dictionaries.
    """
    interfaces = []

    try:
        hostname = socket.gethostname()
        # Get all IPs associated with hostname
        ips = socket.getaddrinfo(hostname, None)
        seen = set()
        for ip_info in ips:
            family, _, _, _, addr = ip_info
            ip = addr[0]
            if ip not in seen:
                seen.add(ip)
                family_name = 'IPv4' if family == socket.AF_INET else 'IPv6'
                interfaces.append({
                    'ip': ip,
                    'family': family_name,
                    'hostname': hostname,
                })
    except socket.gaierror:
        pass

    # Also try platform-specific commands
    try:
        if platform.system().lower() == 'windows':
            output = subprocess.run(
                ['ipconfig', '/all'], capture_output=True, text=True, timeout=10
            )
            # Parse basic info
            current_adapter = None
            for line in output.stdout.splitlines():
                adapter_match = re.match(r'^(\S.+):$', line.strip())
                if adapter_match:
                    current_adapter = adapter_match.group(1)

                ip_match = re.search(r'IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match and current_adapter:
                    ip = ip_match.group(1)
                    if not any(iface['ip'] == ip for iface in interfaces):
                        interfaces.append({
                            'ip': ip,
                            'family': 'IPv4',
                            'adapter': current_adapter,
                        })

                mac_match = re.search(r'Physical.*?:\s*([0-9A-Fa-f-]{17})', line)
                if mac_match and current_adapter:
                    mac = mac_match.group(1)
                    for iface in interfaces:
                        if iface.get('adapter') == current_adapter:
                            iface['mac'] = mac
        else:
            output = subprocess.run(
                ['ip', 'addr'], capture_output=True, text=True, timeout=10
            )
            current_iface = None
            for line in output.stdout.splitlines():
                iface_match = re.match(r'^\d+:\s+(\S+):', line)
                if iface_match:
                    current_iface = iface_match.group(1)

                inet_match = re.search(r'inet\s+(\S+)', line)
                if inet_match and current_iface:
                    ip = inet_match.group(1).split('/')[0]
                    if not any(iface['ip'] == ip for iface in interfaces):
                        interfaces.append({
                            'ip': ip,
                            'family': 'IPv4',
                            'interface': current_iface,
                        })

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return interfaces


def run_recon(args):
    """
    Execute network reconnaissance operations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with reconnaissance results.
    """
    print_module_banner("Network Recon", "Host discovery, traceroute, OS fingerprinting")

    results = {}

    # List interfaces
    if args.interfaces:
        print_sub_header("Network Interfaces")
        interfaces = _list_interfaces()

        if interfaces:
            for iface in interfaces:
                name = iface.get('adapter') or iface.get('interface') or iface.get('hostname', 'unknown')
                mac = iface.get('mac', '')
                mac_str = f"  {dim('MAC:')} {mac}" if mac else ""
                print(f"    {success('●')} {bold(iface['ip']):<20} {dim(iface['family']):<6} {dim(name)}{mac_str}")
        else:
            print_warning("Could not enumerate interfaces.")

        results['interfaces'] = interfaces

    # Ping sweep
    if args.sweep:
        print_sub_header("Ping Sweep")
        alive = _ping_sweep(args.sweep, threads=args.threads)

        alive.sort(key=lambda x: [int(p) for p in x['ip'].split('.')] if '.' in x['ip'] else [0])

        if alive:
            print()
            print_success(f"Found {len(alive)} alive hosts:")
            print()
            print(f"    {'IP ADDRESS':<18} {'TTL':<6} {'LATENCY':<12} {'OS GUESS'}")
            print(f"    {dim('─' * 60)}")
            for host in alive:
                ttl = str(host['ttl']) if host['ttl'] else '?'
                lat = f"{host['latency']}ms" if host['latency'] else '?'
                os_g = host['os_guess'] or 'Unknown'
                print(f"    {bold(host['ip']):<18} {ttl:<6} {lat:<12} {dim(os_g)}")
        else:
            print_warning("No alive hosts found.")

        results['sweep'] = alive

    # Traceroute
    if args.traceroute:
        print_sub_header("Traceroute")
        hops = _traceroute(args.traceroute)
        results['traceroute'] = hops

        print()
        print_result("Total hops", str(len(hops)))
        responsive = sum(1 for h in hops if h['ip'] != '*')
        print_result("Responsive hops", str(responsive))

    # OS detection
    if args.os_detect:
        print_sub_header("OS Detection")
        os_result = _os_detect(args.os_detect)

        print()
        print_result("Target", os_result['target'])
        print_result("TTL", str(os_result['ttl']) if os_result['ttl'] else 'N/A')
        print_result("OS Guess", os_result['os_guess'] or 'Unknown')
        if os_result.get('latency'):
            print_result("Latency", f"{os_result['latency']}ms")

        if os_result['details']:
            print()
            print_info("Open service ports suggest:")
            for hint in os_result['details']:
                print(f"    {dim('●')} {hint}")

        results['os_detect'] = os_result

    # ARP scan
    if args.arp:
        print_sub_header("ARP Scan")
        print_info(f"ARP scanning {args.arp}...")

        try:
            if platform.system().lower() == 'windows':
                # Use arp -a on Windows
                output = subprocess.run(
                    ['arp', '-a'], capture_output=True, text=True, timeout=15
                )
                arp_entries = []
                for line in output.stdout.splitlines():
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
                    if match:
                        arp_entries.append({
                            'ip': match.group(1),
                            'mac': match.group(2),
                            'type': match.group(3),
                        })

                if arp_entries:
                    print()
                    print(f"    {'IP ADDRESS':<18} {'MAC ADDRESS':<20} {'TYPE'}")
                    print(f"    {dim('─' * 50)}")
                    for entry in arp_entries:
                        print(f"    {bold(entry['ip']):<18} {entry['mac']:<20} {dim(entry['type'])}")
                else:
                    print_warning("No ARP entries found.")

                results['arp'] = arp_entries
            else:
                print_warning("ARP scanning requires 'arping' or 'scapy'. Using arp cache.")
                output = subprocess.run(
                    ['arp', '-n'], capture_output=True, text=True, timeout=15
                )
                print(dim(output.stdout))

        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            print_error(f"ARP scan failed: {e}")

    if not any([args.sweep, args.traceroute, args.os_detect, args.interfaces, args.arp]):
        print_warning("No recon action specified. Use --sweep, --traceroute, --os-detect, --interfaces, or --arp.")

    return {'recon': results}
