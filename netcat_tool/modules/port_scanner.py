"""
Cyber_NetCAT — Port Scanner Module

Supports TCP Connect, TCP SYN (stealth), and UDP scanning with
multi-threading, service detection, and configurable parameters.
"""

import socket
import struct
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from netcat_tool.utils.colors import (
    print_header, print_sub_header, print_info, print_success,
    print_error, print_warning, print_result, success, error,
    warning, info, dim, bold, progress_bar
)
from netcat_tool.utils.banner import print_module_banner
from netcat_tool.utils.validators import parse_ports, parse_targets, resolve_target


# Common service names for well-known ports
COMMON_SERVICES = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
    110: 'POP3', 111: 'RPCBind', 119: 'NNTP', 123: 'NTP',
    135: 'MSRPC', 137: 'NetBIOS-NS', 138: 'NetBIOS-DGM',
    139: 'NetBIOS-SSN', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap',
    179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'Microsoft-DS',
    465: 'SMTPS', 514: 'Syslog', 515: 'LPD', 587: 'Submission',
    636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1080: 'SOCKS', 1433: 'MSSQL', 1434: 'MSSQL-UDP',
    1521: 'Oracle', 1723: 'PPTP', 2049: 'NFS',
    2082: 'cPanel', 2083: 'cPanel-SSL', 2086: 'WHM', 2087: 'WHM-SSL',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 5901: 'VNC-1', 6379: 'Redis',
    8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 8888: 'HTTP-Alt',
    9090: 'WebSM', 9200: 'Elasticsearch', 27017: 'MongoDB',
}


def get_service_name(port):
    """Get the common service name for a port."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port)
    except (socket.error, OSError):
        return "unknown"


def tcp_connect_scan(target, port, timeout):
    """
    Perform a TCP connect scan on a single port.

    Args:
        target: Target IP address.
        port: Port number to scan.
        timeout: Connection timeout in seconds.

    Returns:
        Tuple of (port, state, service_name).
        state is 'open', 'closed', or 'filtered'.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            return (port, 'open', get_service_name(port))
        else:
            return (port, 'closed', get_service_name(port))
    except socket.timeout:
        return (port, 'filtered', get_service_name(port))
    except socket.error:
        return (port, 'filtered', get_service_name(port))


def tcp_syn_scan(target, port, timeout):
    """
    Perform a TCP SYN (stealth) scan using raw sockets.
    Requires elevated privileges (admin/root).

    Falls back to connect scan if raw sockets are unavailable.

    Args:
        target: Target IP address.
        port: Port number.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (port, state, service_name).
    """
    try:
        # Attempt raw socket — requires privileges
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.settimeout(timeout)

        # Build SYN packet
        src_port = 40000 + (port % 25000)

        # TCP header: src_port, dst_port, seq, ack, offset_flags, window, checksum, urg
        tcp_flags = 0x02  # SYN
        offset = 5 << 4
        header = struct.pack('!HHIIBBHHH',
                             src_port, port, 0, 0, offset, tcp_flags, 65535, 0, 0)

        sock.sendto(header, (target, port))

        # Receive response
        data = sock.recv(1024)
        sock.close()

        if data:
            # Parse TCP flags from response
            tcp_header = data[20:40]
            if len(tcp_header) >= 14:
                flags = tcp_header[13]
                if flags & 0x12:  # SYN-ACK
                    return (port, 'open', get_service_name(port))
                elif flags & 0x14:  # RST-ACK
                    return (port, 'closed', get_service_name(port))

        return (port, 'filtered', get_service_name(port))

    except (PermissionError, OSError):
        # Fall back to connect scan
        return tcp_connect_scan(target, port, timeout)


def udp_scan(target, port, timeout):
    """
    Perform a UDP scan on a single port.

    Args:
        target: Target IP address.
        port: Port number.
        timeout: Timeout in seconds.

    Returns:
        Tuple of (port, state, service_name).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Send empty UDP datagram
        sock.sendto(b'\x00', (target, port))

        try:
            data, addr = sock.recvfrom(1024)
            sock.close()
            return (port, 'open', get_service_name(port))
        except socket.timeout:
            sock.close()
            return (port, 'open|filtered', get_service_name(port))

    except socket.error:
        return (port, 'closed', get_service_name(port))


def run_scan(args):
    """
    Execute the port scanning operation.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with scan results.
    """
    print_module_banner("Port Scanner", "TCP/UDP port scanning with service detection")

    # Parse targets and ports
    targets = parse_targets(args.target)
    ports = parse_ports(args.ports)
    timeout = args.timeout
    threads = args.threads
    delay = args.delay

    # Select scan function
    if args.udp:
        scan_func = udp_scan
        scan_type = "UDP"
    elif args.syn:
        scan_func = tcp_syn_scan
        scan_type = "TCP SYN (Stealth)"
    else:
        scan_func = tcp_connect_scan
        scan_type = "TCP Connect"

    all_results = {}

    for target_ip in targets:
        print_sub_header(f"Scanning {target_ip}")
        print_info(f"Scan type: {scan_type}")
        print_info(f"Ports: {len(ports)} | Threads: {threads} | Timeout: {timeout}s")
        print()

        open_ports = []
        closed_ports = []
        filtered_ports = []
        scanned = 0
        total = len(ports)
        lock = threading.Lock()

        start_time = time.time()

        def scan_port(port):
            nonlocal scanned
            if delay > 0:
                time.sleep(delay)
            result = scan_func(target_ip, port, timeout)
            with lock:
                scanned += 1
                if result[1] == 'open':
                    open_ports.append(result)
                elif result[1] == 'closed':
                    closed_ports.append(result)
                else:
                    filtered_ports.append(result)
                progress_bar(scanned, total, prefix="Scanning")
            return result

        # Execute scan with thread pool
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, p): p for p in ports}
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception:
                    pass

        elapsed = time.time() - start_time
        print()

        # Display results
        print_sub_header("Scan Results")

        if open_ports:
            open_ports.sort(key=lambda x: x[0])
            print()
            header_fmt = f"  {'PORT':<10} {'STATE':<15} {'SERVICE':<20}"
            print(f"  {dim('─' * 50)}")
            print(bold(header_fmt))
            print(f"  {dim('─' * 50)}")

            for port, state, service in open_ports:
                state_colored = success(state.upper())
                print(f"  {str(port) + '/tcp' if not args.udp else str(port) + '/udp':<10} {state_colored:<25} {service:<20}")

            print(f"  {dim('─' * 50)}")
        else:
            print_warning("No open ports found.")

        # Summary
        print()
        print_result("Open ports", str(len(open_ports)))
        print_result("Closed ports", str(len(closed_ports)))
        print_result("Filtered ports", str(len(filtered_ports)))
        print_result("Scan duration", f"{elapsed:.2f}s")
        print_result("Scan rate", f"{total / elapsed:.0f} ports/sec" if elapsed > 0 else "N/A")

        all_results[target_ip] = {
            'scan_type': scan_type,
            'open': [(p, s, svc) for p, s, svc in open_ports],
            'closed_count': len(closed_ports),
            'filtered_count': len(filtered_ports),
            'duration': round(elapsed, 2),
            'total_scanned': total,
        }

    return {'port_scan': all_results}
