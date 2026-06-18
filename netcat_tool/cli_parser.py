"""
CLI argument parser for Cyber_NetCAT.
Defines all subcommands and their arguments using argparse.
"""

import argparse
from netcat_tool import __version__


def build_parser():
    """
    Build and return the main argument parser with all subcommands.

    Returns:
        argparse.ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        prog="netcat-tool",
        description="Cyber_NetCAT — Comprehensive CLI Network Security Assessment Tool",
        epilog="Use '%(prog)s <command> --help' for detailed help on each command.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        '-V', '--version', action='version', version=f'Cyber_NetCAT v{__version__}'
    )
    parser.add_argument(
        '-v', '--verbose', action='store_true', help='Enable verbose/debug output'
    )
    parser.add_argument(
        '-o', '--output', type=str, default=None,
        help='Save results to JSON file'
    )
    parser.add_argument(
        '--timeout', type=float, default=2.0,
        help='Default connection timeout in seconds (default: 2.0)'
    )
    parser.add_argument(
        '--no-banner', action='store_true',
        help='Suppress the startup banner'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # ─── 1. Port Scanner ──────────────────────────────────────────────
    scan_parser = subparsers.add_parser(
        'scan', help='TCP/UDP port scanning',
        description='Scan target hosts for open ports using TCP connect, SYN, or UDP scans.'
    )
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP, hostname, or CIDR range')
    scan_parser.add_argument('-p', '--ports', default='common', help='Port(s): single, range (1-1000), comma-separated, or "common"/"all"')
    scan_parser.add_argument('--udp', action='store_true', help='Perform UDP scan instead of TCP')
    scan_parser.add_argument('--syn', action='store_true', help='Perform TCP SYN (stealth) scan (requires privileges)')
    scan_parser.add_argument('--threads', type=int, default=100, help='Number of concurrent threads (default: 100)')
    scan_parser.add_argument('--delay', type=float, default=0, help='Delay between scans in seconds (default: 0)')
    scan_parser.add_argument('--service', action='store_true', default=True, help='Resolve service names (default: on)')

    # ─── 2. Banner Grabber ────────────────────────────────────────────
    banner_parser = subparsers.add_parser(
        'banner', help='Grab service banners from open ports',
        description='Connect to specified ports and retrieve service banners for identification.'
    )
    banner_parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    banner_parser.add_argument('-p', '--ports', required=True, help='Port(s) to grab banners from')
    banner_parser.add_argument('--probe', action='store_true', help='Send protocol-specific probes (HTTP, FTP, SMTP)')

    # ─── 3. DNS Enumeration ──────────────────────────────────────────
    dns_parser = subparsers.add_parser(
        'dns', help='DNS enumeration and analysis',
        description='Perform DNS lookups, subdomain enumeration, and zone transfer attempts.'
    )
    dns_parser.add_argument('-d', '--domain', required=True, help='Target domain name')
    dns_parser.add_argument('--type', dest='record_types', default='A',
                            help='DNS record types, comma-separated (A, AAAA, MX, NS, TXT, CNAME, SOA)')
    dns_parser.add_argument('--zone-transfer', action='store_true', help='Attempt DNS zone transfer (AXFR)')
    dns_parser.add_argument('--subdomains', action='store_true', help='Enumerate subdomains via brute force')
    dns_parser.add_argument('--wordlist', type=str, default=None, help='Custom subdomain wordlist file')
    dns_parser.add_argument('--reverse', type=str, default=None, help='Reverse DNS lookup for an IP address')
    dns_parser.add_argument('--server', type=str, default=None, help='Custom DNS server to query')

    # ─── 4. Network Reconnaissance ───────────────────────────────────
    recon_parser = subparsers.add_parser(
        'recon', help='Network reconnaissance and host discovery',
        description='Discover hosts, perform ping sweeps, traceroute, and OS fingerprinting.'
    )
    recon_parser.add_argument('--sweep', type=str, default=None, help='Ping sweep a CIDR range (e.g., 192.168.1.0/24)')
    recon_parser.add_argument('--traceroute', type=str, default=None, help='Traceroute to target host')
    recon_parser.add_argument('--os-detect', type=str, default=None, help='OS detection via TTL analysis on target')
    recon_parser.add_argument('--interfaces', action='store_true', help='List local network interfaces')
    recon_parser.add_argument('--arp', type=str, default=None, help='ARP scan on local network CIDR')
    recon_parser.add_argument('--threads', type=int, default=50, help='Threads for sweep (default: 50)')

    # ─── 5. Vulnerability Scanner ────────────────────────────────────
    vuln_parser = subparsers.add_parser(
        'vulnscan', help='Vulnerability assessment',
        description='Check for known vulnerabilities, weak SSL/TLS, insecure HTTP headers.'
    )
    vuln_parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    vuln_parser.add_argument('-p', '--ports', default='common', help='Ports to check')
    vuln_parser.add_argument('--ssl-check', action='store_true', help='Check SSL/TLS configuration')
    vuln_parser.add_argument('--headers', action='store_true', help='Analyze HTTP security headers')
    vuln_parser.add_argument('--cve', action='store_true', help='Check against known CVE database')
    vuln_parser.add_argument('--full', action='store_true', help='Run all vulnerability checks')

    # ─── 6. Packet Crafter ───────────────────────────────────────────
    craft_parser = subparsers.add_parser(
        'craft', help='Craft and send custom packets',
        description='Create custom TCP, UDP, or ICMP packets with specified parameters.'
    )
    craft_parser.add_argument('-t', '--target', required=True, help='Target IP address')
    craft_parser.add_argument('-p', '--port', type=int, default=80, help='Target port (default: 80)')
    craft_parser.add_argument('--tcp', action='store_true', help='Send TCP packet')
    craft_parser.add_argument('--udp', action='store_true', help='Send UDP packet')
    craft_parser.add_argument('--icmp', action='store_true', help='Send ICMP packet')
    craft_parser.add_argument('--flags', type=str, default='SYN', help='TCP flags: SYN, ACK, FIN, RST, PSH, URG (comma-separated)')
    craft_parser.add_argument('--data', type=str, default='', help='Payload data to include')
    craft_parser.add_argument('--count', type=int, default=1, help='Number of packets to send (default: 1)')
    craft_parser.add_argument('--spoof', type=str, default=None, help='Spoof source IP address')
    craft_parser.add_argument('--flood', action='store_true', help='Flood mode (send continuously)')

    # ─── 7. Reverse/Bind Shell ───────────────────────────────────────
    shell_parser = subparsers.add_parser(
        'shell', help='Reverse/Bind shell operations',
        description='Start a reverse shell listener, connect back to a listener, or bind a shell.'
    )
    shell_group = shell_parser.add_mutually_exclusive_group(required=True)
    shell_group.add_argument('--listen', action='store_true', help='Start a reverse shell listener')
    shell_group.add_argument('--connect', type=str, default=None, help='Connect to a listener (IP address)')
    shell_group.add_argument('--bind', action='store_true', help='Bind shell on this host')
    shell_parser.add_argument('-p', '--port', type=int, required=True, help='Port to listen on or connect to')
    shell_parser.add_argument('--encrypt', action='store_true', help='Enable XOR encryption for comms')
    shell_parser.add_argument('--key', type=str, default='NetCAT', help='Encryption key (default: NetCAT)')

    # ─── 8. File Transfer ────────────────────────────────────────────
    transfer_parser = subparsers.add_parser(
        'transfer', help='Transfer files over TCP',
        description='Send or receive files over a TCP connection with integrity verification.'
    )
    transfer_group = transfer_parser.add_mutually_exclusive_group(required=True)
    transfer_group.add_argument('--send', type=str, default=None, help='File path to send')
    transfer_group.add_argument('--receive', action='store_true', help='Receive a file')
    transfer_parser.add_argument('-t', '--target', type=str, default=None, help='Target IP (required for --send)')
    transfer_parser.add_argument('-p', '--port', type=int, required=True, help='Port for transfer')
    transfer_parser.add_argument('--output-dir', type=str, default='.', help='Output directory for received files')
    transfer_parser.add_argument('--compress', action='store_true', help='Compress file before transfer')

    # ─── 9. Brute Force ──────────────────────────────────────────────
    brute_parser = subparsers.add_parser(
        'brute', help='Brute force authentication testing',
        description='Test credentials against SSH, FTP, or HTTP Basic Auth services.'
    )
    brute_proto = brute_parser.add_mutually_exclusive_group(required=True)
    brute_proto.add_argument('--ssh', action='store_true', help='Brute force SSH')
    brute_proto.add_argument('--ftp', action='store_true', help='Brute force FTP')
    brute_proto.add_argument('--http', action='store_true', help='Brute force HTTP Basic Auth')
    brute_parser.add_argument('-t', '--target', required=True, help='Target IP or hostname')
    brute_parser.add_argument('-p', '--port', type=int, default=None, help='Target port (auto-detected if not set)')
    brute_parser.add_argument('-u', '--username', required=True, help='Username or username file')
    brute_parser.add_argument('-w', '--wordlist', required=True, help='Password wordlist file')
    brute_parser.add_argument('--delay', type=float, default=0.5, help='Delay between attempts (default: 0.5s)')
    brute_parser.add_argument('--threads', type=int, default=4, help='Concurrent threads (default: 4)')
    brute_parser.add_argument('--url', type=str, default='/', help='URL path for HTTP brute force (default: /)')
    brute_parser.add_argument('--stop-on-success', action='store_true', default=True, help='Stop on first valid credential')

    # ─── 10. Traffic Analyzer ────────────────────────────────────────
    sniff_parser = subparsers.add_parser(
        'sniff', help='Capture and analyze network traffic',
        description='Capture live network traffic with protocol filtering and analysis.'
    )
    sniff_parser.add_argument('--interface', type=str, default=None, help='Network interface to capture on')
    sniff_parser.add_argument('--filter', type=str, default=None,
                              help='Protocol filter: tcp, udp, icmp, arp, http, dns')
    sniff_parser.add_argument('--count', type=int, default=50, help='Number of packets to capture (default: 50)')
    sniff_parser.add_argument('--hex', action='store_true', help='Show hex dump of packets')
    sniff_parser.add_argument('--save', type=str, default=None, help='Save capture to file')
    sniff_parser.add_argument('--stats', action='store_true', help='Show capture statistics summary')

    return parser
