"""
Input validation utilities for Cyber_NetCAT.
Validates IP addresses, port ranges, hostnames, and other user inputs.
"""

import re
import socket
import ipaddress


def validate_ip(ip_str):
    """
    Validate an IPv4 or IPv6 address.

    Args:
        ip_str: IP address string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def validate_cidr(cidr_str):
    """
    Validate a CIDR network notation (e.g., 192.168.1.0/24).

    Args:
        cidr_str: CIDR string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False


def validate_hostname(hostname):
    """
    Validate a hostname string.

    Args:
        hostname: Hostname to validate.

    Returns:
        True if valid, False otherwise.
    """
    if len(hostname) > 253:
        return False
    pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$'
    )
    return bool(pattern.match(hostname))


def resolve_target(target):
    """
    Resolve a target to an IP address. Accepts IP addresses and hostnames.

    Args:
        target: IP address or hostname.

    Returns:
        Resolved IP address string.

    Raises:
        ValueError: If the target cannot be resolved.
    """
    if validate_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        raise ValueError(f"Cannot resolve target: {target}")


def parse_ports(port_str):
    """
    Parse a port specification string into a list of port numbers.

    Supports:
        - Single port: '80'
        - Comma-separated: '80,443,8080'
        - Range: '1-1000'
        - Mixed: '22,80,443,8000-9000'
        - Named presets: 'common', 'top100', 'all'

    Args:
        port_str: Port specification string.

    Returns:
        Sorted list of unique port numbers.

    Raises:
        ValueError: If the port string is invalid.
    """
    # Named presets
    presets = {
        'common': [
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123,
            135, 137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465,
            514, 515, 587, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
            2049, 2082, 2083, 2086, 2087, 3306, 3389, 5432, 5900, 5901,
            6379, 8080, 8443, 8888, 9090, 9200, 27017
        ],
        'top100': list(range(1, 101)),
        'all': list(range(1, 65536)),
    }

    port_str = port_str.strip().lower()
    if port_str in presets:
        return presets[port_str]

    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start, end = int(start.strip()), int(end.strip())
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(
                        f"Invalid port range: {part} (must be 1-65535)"
                    )
                ports.update(range(start, end + 1))
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid port range '{part}': {e}")
        else:
            try:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(
                        f"Port {port} out of range (must be 1-65535)"
                    )
                ports.add(port)
            except ValueError:
                raise ValueError(f"Invalid port number: '{part}'")

    return sorted(ports)


def parse_targets(target_str):
    """
    Parse a target specification into a list of IP addresses.

    Supports:
        - Single IP: '192.168.1.1'
        - CIDR range: '192.168.1.0/24'
        - Hostname: 'example.com'
        - Comma-separated: '192.168.1.1,192.168.1.2'

    Args:
        target_str: Target specification string.

    Returns:
        List of IP address strings.
    """
    targets = []
    for part in target_str.split(','):
        part = part.strip()
        if '/' in part and validate_cidr(part):
            network = ipaddress.ip_network(part, strict=False)
            targets.extend(str(host) for host in network.hosts())
        elif validate_ip(part):
            targets.append(part)
        else:
            try:
                resolved = resolve_target(part)
                targets.append(resolved)
            except ValueError:
                raise ValueError(f"Cannot resolve target: '{part}'")
    return targets


def validate_port(port):
    """
    Validate a single port number.

    Args:
        port: Port number to validate.

    Returns:
        True if valid (1-65535), False otherwise.
    """
    try:
        port = int(port)
        return 1 <= port <= 65535
    except (ValueError, TypeError):
        return False


def validate_timeout(timeout):
    """
    Validate a timeout value.

    Args:
        timeout: Timeout in seconds.

    Returns:
        Float timeout if valid.

    Raises:
        ValueError: If timeout is invalid.
    """
    try:
        timeout = float(timeout)
        if timeout <= 0:
            raise ValueError("Timeout must be positive")
        return timeout
    except (ValueError, TypeError):
        raise ValueError(f"Invalid timeout value: {timeout}")
