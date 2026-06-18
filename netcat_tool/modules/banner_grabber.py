"""
Cyber_NetCAT — Banner Grabber Module

Connects to specified ports and retrieves service banners
for identification. Supports protocol-specific probing.
"""

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from netcat_tool.utils.colors import (
    print_header, print_sub_header, print_info, print_success,
    print_error, print_warning, print_result, success, error,
    warning, info, dim, bold
)
from netcat_tool.utils.banner import print_module_banner
from netcat_tool.utils.validators import parse_ports, resolve_target


# Protocol-specific probe payloads
PROBES = {
    'http': b'HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n',
    'ftp': None,   # FTP sends banner on connect
    'smtp': None,  # SMTP sends banner on connect
    'ssh': None,   # SSH sends banner on connect
    'pop3': None,  # POP3 sends banner on connect
    'imap': None,  # IMAP sends banner on connect
}

# Ports that typically use specific protocols
PORT_PROTOCOL_MAP = {
    21: 'ftp', 22: 'ssh', 25: 'smtp', 80: 'http',
    110: 'pop3', 143: 'imap', 443: 'https',
    587: 'smtp', 993: 'imaps', 995: 'pop3s',
    8080: 'http', 8443: 'https',
}


def grab_banner(target, port, timeout, probe=False):
    """
    Grab the service banner from a target port.

    Args:
        target: Target IP address.
        port: Port number.
        timeout: Connection timeout.
        probe: Whether to send protocol-specific probes.

    Returns:
        Dictionary with port, banner, and protocol info.
    """
    result = {
        'port': port,
        'banner': None,
        'protocol': PORT_PROTOCOL_MAP.get(port, 'unknown'),
        'ssl': False,
        'error': None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))

        # Check if SSL/TLS port
        use_ssl = port in (443, 465, 636, 993, 995, 8443)
        if use_ssl:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)
                result['ssl'] = True
                result['ssl_version'] = sock.version()

                # Get certificate info
                cert = sock.getpeercert(binary_form=False)
                if cert:
                    result['cert_subject'] = dict(x[0] for x in cert.get('subject', []))
                    result['cert_issuer'] = dict(x[0] for x in cert.get('issuer', []))
                    result['cert_expires'] = cert.get('notAfter', 'N/A')
            except ssl.SSLError:
                # Not actually SSL, reconnect without it
                sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                sock.connect((target, port))
                result['ssl'] = False

        # Send probe if applicable
        protocol = PORT_PROTOCOL_MAP.get(port, '')
        if probe and protocol in PROBES:
            probe_data = PROBES[protocol]
            if probe_data:
                if b'{host}' in probe_data:
                    probe_data = probe_data.replace(b'{host}', target.encode())
                sock.send(probe_data)

        # Receive banner
        try:
            banner_data = sock.recv(4096)
            if banner_data:
                # Try to decode, handle binary data
                try:
                    result['banner'] = banner_data.decode('utf-8', errors='replace').strip()
                except Exception:
                    result['banner'] = banner_data.hex()
        except socket.timeout:
            # Some services need a probe to respond
            if not probe:
                sock.send(b'\r\n')
                try:
                    banner_data = sock.recv(4096)
                    if banner_data:
                        result['banner'] = banner_data.decode('utf-8', errors='replace').strip()
                except Exception:
                    result['banner'] = None

        sock.close()

    except socket.timeout:
        result['error'] = 'Connection timed out'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
    except socket.error as e:
        result['error'] = str(e)

    return result


def run_banner_grab(args):
    """
    Execute the banner grabbing operation.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with banner grab results.
    """
    print_module_banner("Banner Grabber", "Service identification via banner collection")

    target = resolve_target(args.target)
    ports = parse_ports(args.ports)
    timeout = args.timeout
    probe = args.probe

    print_info(f"Target: {target} ({args.target})")
    print_info(f"Ports: {len(ports)} | Probe mode: {'ON' if probe else 'OFF'}")
    print()

    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(grab_banner, target, port, timeout, probe): port
            for port in ports
        }
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    # Sort by port number
    results.sort(key=lambda x: x['port'])

    # Display results
    print_sub_header("Banner Results")
    print()

    banners_found = 0
    for r in results:
        port = r['port']
        banner = r['banner']
        protocol = r['protocol']
        ssl_info = r['ssl']

        if r['error']:
            print(f"  {dim(str(port) + '/tcp'):<15} {error('✗')} {dim(r['error'])}")
            continue

        if banner:
            banners_found += 1
            # Truncate long banners for display
            display_banner = banner[:120]
            if len(banner) > 120:
                display_banner += dim('...')

            ssl_badge = f" {info('[SSL]')}" if ssl_info else ""
            print(f"  {bold(str(port) + '/tcp'):<15} {success('✓')} {info(protocol.upper())}{ssl_badge}")
            print(f"  {'':15} {dim('└─')} {display_banner}")

            if r.get('ssl_version'):
                print(f"  {'':15} {dim('   SSL:')} {r['ssl_version']}")
            if r.get('cert_subject'):
                cn = r['cert_subject'].get('commonName', 'N/A')
                print(f"  {'':15} {dim('   CN:')} {cn}")
            if r.get('cert_expires'):
                print(f"  {'':15} {dim('   Expires:')} {r['cert_expires']}")
            print()
        else:
            print(f"  {dim(str(port) + '/tcp'):<15} {warning('?')} {dim('No banner received')}")

    # Summary
    print(f"  {dim('─' * 50)}")
    print_result("Total ports probed", str(len(results)))
    print_result("Banners collected", str(banners_found))
    print_result("Errors", str(sum(1 for r in results if r['error'])))

    return {
        'banner_grab': {
            'target': target,
            'results': results,
            'banners_found': banners_found,
        }
    }
