"""
Cyber_NetCAT — Traffic Analyzer Module

Raw socket packet capture with protocol filtering, hex dump,
source/destination analysis, and summary statistics.
"""

import socket
import struct
import time
import os
import json
from datetime import datetime
from collections import defaultdict

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold, progress_bar
)
from netcat_tool.utils.banner import print_module_banner


# Protocol numbers
PROTOCOLS = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    2: 'IGMP',
}

# Common port-to-protocol mapping
PORT_APPS = {
    20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
    3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Proxy',
}


def _hex_dump(data, length=16):
    """
    Create a hex dump string from binary data.

    Args:
        data: Binary data to dump.
        length: Bytes per line.

    Returns:
        Formatted hex dump string.
    """
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"    {i:04x}  {hex_part:<{length * 3}}  {ascii_part}")
    return '\n'.join(lines)


def _parse_ip_header(data):
    """
    Parse an IP header from raw packet data.

    Args:
        data: Raw packet bytes.

    Returns:
        Dictionary with parsed IP header fields.
    """
    if len(data) < 20:
        return None

    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = (version_ihl & 0xF) * 4

    return {
        'version': version,
        'ihl': ihl,
        'tos': iph[1],
        'total_length': iph[2],
        'id': iph[3],
        'ttl': iph[5],
        'protocol': iph[6],
        'protocol_name': PROTOCOLS.get(iph[6], f'Unknown({iph[6]})'),
        'checksum': iph[7],
        'src_ip': socket.inet_ntoa(iph[8]),
        'dst_ip': socket.inet_ntoa(iph[9]),
    }


def _parse_tcp_header(data):
    """Parse a TCP header from data."""
    if len(data) < 20:
        return None

    tcph = struct.unpack('!HHIIBBHHH', data[:20])

    flags_byte = tcph[5]
    flags = []
    if flags_byte & 0x01: flags.append('FIN')
    if flags_byte & 0x02: flags.append('SYN')
    if flags_byte & 0x04: flags.append('RST')
    if flags_byte & 0x08: flags.append('PSH')
    if flags_byte & 0x10: flags.append('ACK')
    if flags_byte & 0x20: flags.append('URG')

    return {
        'src_port': tcph[0],
        'dst_port': tcph[1],
        'seq': tcph[2],
        'ack': tcph[3],
        'flags': flags,
        'flags_str': ','.join(flags) if flags else 'NONE',
        'window': tcph[6],
        'checksum': tcph[7],
        'app_src': PORT_APPS.get(tcph[0], ''),
        'app_dst': PORT_APPS.get(tcph[1], ''),
    }


def _parse_udp_header(data):
    """Parse a UDP header from data."""
    if len(data) < 8:
        return None

    udph = struct.unpack('!HHHH', data[:8])

    return {
        'src_port': udph[0],
        'dst_port': udph[1],
        'length': udph[2],
        'checksum': udph[3],
        'app_src': PORT_APPS.get(udph[0], ''),
        'app_dst': PORT_APPS.get(udph[1], ''),
    }


def _parse_icmp_header(data):
    """Parse an ICMP header from data."""
    if len(data) < 8:
        return None

    icmph = struct.unpack('!BBHHH', data[:8])

    icmp_types = {
        0: 'Echo Reply', 3: 'Dest Unreachable', 4: 'Source Quench',
        5: 'Redirect', 8: 'Echo Request', 11: 'Time Exceeded',
    }

    return {
        'type': icmph[0],
        'type_name': icmp_types.get(icmph[0], f'Type {icmph[0]}'),
        'code': icmph[1],
        'checksum': icmph[2],
        'id': icmph[3],
        'seq': icmph[4],
    }


def _format_packet(pkt_num, ip_header, transport_header, protocol, show_hex=False, raw_data=None):
    """Format a parsed packet for display."""
    ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]

    if protocol == 'TCP' and transport_header:
        src = f"{ip_header['src_ip']}:{transport_header['src_port']}"
        dst = f"{ip_header['dst_ip']}:{transport_header['dst_port']}"
        flags = transport_header['flags_str']
        app = transport_header['app_src'] or transport_header['app_dst']
        app_str = f" [{app}]" if app else ""

        print(
            f"  {dim(f'#{pkt_num:<4}')} {dim(ts)} "
            f"{info('TCP')} {bold(src)} → {bold(dst)} "
            f"[{warning(flags)}]{dim(app_str)} "
            f"TTL={ip_header['ttl']}"
        )

    elif protocol == 'UDP' and transport_header:
        src = f"{ip_header['src_ip']}:{transport_header['src_port']}"
        dst = f"{ip_header['dst_ip']}:{transport_header['dst_port']}"
        app = transport_header['app_src'] or transport_header['app_dst']
        app_str = f" [{app}]" if app else ""

        print(
            f"  {dim(f'#{pkt_num:<4}')} {dim(ts)} "
            f"{success('UDP')} {bold(src)} → {bold(dst)} "
            f"len={transport_header['length']}{dim(app_str)} "
            f"TTL={ip_header['ttl']}"
        )

    elif protocol == 'ICMP' and transport_header:
        src = ip_header['src_ip']
        dst = ip_header['dst_ip']

        print(
            f"  {dim(f'#{pkt_num:<4}')} {dim(ts)} "
            f"{warning('ICMP')} {bold(src)} → {bold(dst)} "
            f"{transport_header['type_name']} "
            f"id={transport_header['id']} seq={transport_header['seq']} "
            f"TTL={ip_header['ttl']}"
        )

    else:
        print(
            f"  {dim(f'#{pkt_num:<4}')} {dim(ts)} "
            f"{dim(protocol)} {ip_header['src_ip']} → {ip_header['dst_ip']} "
            f"TTL={ip_header['ttl']}"
        )

    if show_hex and raw_data:
        print(_hex_dump(raw_data[:128]))
        print()


def run_sniff(args):
    """
    Execute traffic capture and analysis.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with capture results.
    """
    print_module_banner("Traffic Analyzer", "Packet capture and protocol analysis")

    count = args.count
    protocol_filter = args.filter.upper() if args.filter else None
    show_hex = args.hex
    save_file = args.save
    show_stats = args.stats

    print_info(f"Capture count: {count}")
    if protocol_filter:
        print_info(f"Filter: {protocol_filter}")
    if save_file:
        print_info(f"Saving to: {save_file}")
    print()

    # Protocol filter mapping
    filter_map = {
        'TCP': 6, 'UDP': 17, 'ICMP': 1,
        'HTTP': 6, 'DNS': 17, 'ARP': None,
    }
    filter_proto = filter_map.get(protocol_filter) if protocol_filter else None

    # Application-level filters
    app_port_filter = None
    if protocol_filter == 'HTTP':
        app_port_filter = [80, 8080, 443, 8443]
    elif protocol_filter == 'DNS':
        app_port_filter = [53]

    # Stats tracking
    stats = {
        'total': 0,
        'protocols': defaultdict(int),
        'src_ips': defaultdict(int),
        'dst_ips': defaultdict(int),
        'src_ports': defaultdict(int),
        'dst_ports': defaultdict(int),
        'bytes': 0,
    }

    captured_packets = []

    try:
        # Create raw socket
        import platform as plat

        local_ip = None

        if plat.system().lower() == 'windows':
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

            # Determine the best local IP to bind to
            if args.interface:
                # User specified an interface/IP directly
                local_ip = args.interface
            else:
                # Auto-detect the primary network interface
                # gethostbyname often returns the wrong adapter (e.g. VirtualBox)
                # Instead, connect to an external IP to find the real interface
                try:
                    detect_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    detect_sock.connect(('8.8.8.8', 80))
                    local_ip = detect_sock.getsockname()[0]
                    detect_sock.close()
                except Exception:
                    # Fallback to hostname resolution
                    local_ip = socket.gethostbyname(socket.gethostname())

            print_info(f"Binding to interface: {local_ip}")

            sock.bind((local_ip, 0))
            # Include IP headers in received data
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Enable promiscuous mode (captures ALL traffic on the network)
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                print_success("Promiscuous mode enabled — capturing all network traffic")
            except (AttributeError, OSError) as e:
                print_warning(f"Could not enable promiscuous mode: {e}")
                print_warning("Capturing own traffic only. Run as Administrator for full capture.")

            # Set a timeout so the loop doesn't block forever
            sock.settimeout(2.0)

        else:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            if args.interface:
                sock.bind((args.interface, 0))
            sock.settimeout(2.0)
            local_ip = args.interface or 'all'

        print_sub_header("Live Capture")
        print_info(f"Capturing on {local_ip}...")
        print_info("Generate traffic (browse web, ping, etc.) to see packets")
        print_info("Press Ctrl+C to stop early")
        print()

        captured = 0
        start_time = time.time()
        timeout_count = 0
        max_timeouts = 30  # Stop after 60 seconds of no traffic (30 * 2s timeout)

        while captured < count:
            try:
                raw_data, addr = sock.recvfrom(65535)
                timeout_count = 0  # Reset timeout counter on successful receive

                # Parse IP header
                if plat.system().lower() != 'windows':
                    # Skip Ethernet header on Linux
                    eth_length = 14
                    raw_data = raw_data[eth_length:]

                ip_header = _parse_ip_header(raw_data)
                if not ip_header:
                    continue

                protocol = ip_header['protocol']
                protocol_name = ip_header['protocol_name']
                ihl = ip_header['ihl']

                # Apply protocol filter
                if filter_proto and protocol != filter_proto:
                    continue

                # Parse transport header
                transport_header = None
                transport_data = raw_data[ihl:]

                if protocol == 6:  # TCP
                    transport_header = _parse_tcp_header(transport_data)
                    if app_port_filter and transport_header:
                        if (transport_header['src_port'] not in app_port_filter and
                                transport_header['dst_port'] not in app_port_filter):
                            continue
                elif protocol == 17:  # UDP
                    transport_header = _parse_udp_header(transport_data)
                    if app_port_filter and transport_header:
                        if (transport_header['src_port'] not in app_port_filter and
                                transport_header['dst_port'] not in app_port_filter):
                            continue
                elif protocol == 1:  # ICMP
                    transport_header = _parse_icmp_header(transport_data)

                captured += 1

                # Update stats
                stats['total'] += 1
                stats['protocols'][protocol_name] += 1
                stats['src_ips'][ip_header['src_ip']] += 1
                stats['dst_ips'][ip_header['dst_ip']] += 1
                stats['bytes'] += ip_header['total_length']

                if transport_header and 'src_port' in transport_header:
                    stats['src_ports'][transport_header['src_port']] += 1
                    stats['dst_ports'][transport_header['dst_port']] += 1

                # Display packet
                _format_packet(captured, ip_header, transport_header,
                               protocol_name, show_hex, raw_data)

                # Store for saving
                if save_file:
                    pkt_record = {
                        'num': captured,
                        'timestamp': datetime.now().isoformat(),
                        'ip': ip_header,
                        'transport': transport_header,
                        'size': ip_header['total_length'],
                    }
                    captured_packets.append(pkt_record)

            except socket.timeout:
                timeout_count += 1
                if timeout_count >= max_timeouts:
                    print_warning(f"No traffic detected for {max_timeouts * 2}s. Stopping capture.")
                    break
                # Show waiting indicator every 5 timeouts (10 seconds)
                if timeout_count % 5 == 0:
                    print(f"  {dim(f'[~] Waiting for packets... ({captured}/{count} captured)')}")
                continue

        elapsed = time.time() - start_time

        # Disable promiscuous mode on Windows
        if plat.system().lower() == 'windows':
            try:
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except (AttributeError, OSError):
                pass

        sock.close()

    except PermissionError:
        print_error("Packet capture requires administrator/root privileges.")
        print_info("Run the tool with elevated permissions.")
        return {'sniff': {'error': 'Insufficient permissions'}}
    except OSError as e:
        print_error(f"Capture error: {e}")
        return {'sniff': {'error': str(e)}}

    # Save capture
    if save_file:
        try:
            with open(save_file, 'w', encoding='utf-8') as f:
                json.dump(captured_packets, f, indent=2, default=str)
            print()
            print_success(f"Capture saved to: {save_file}")
        except IOError as e:
            print_error(f"Failed to save capture: {e}")

    # Statistics
    if show_stats or True:
        print()
        print_sub_header("Capture Statistics")
        print()
        print_result("Total packets", str(stats['total']))
        print_result("Total bytes", f"{stats['bytes']:,}")
        print_result("Duration", f"{elapsed:.2f}s")
        print_result("Rate", f"{stats['total'] / elapsed:.1f} pkt/s" if elapsed > 0 else "N/A")

        if stats['protocols']:
            print()
            print_info("Protocol Breakdown:")
            for proto, cnt in sorted(stats['protocols'].items(), key=lambda x: -x[1]):
                pct = cnt / stats['total'] * 100
                bar = "█" * int(pct / 5)
                print(f"    {bold(proto):<8} {cnt:>5} ({pct:>5.1f}%) {success(bar)}")

        if stats['src_ips']:
            print()
            print_info("Top Source IPs:")
            for ip, cnt in sorted(stats['src_ips'].items(), key=lambda x: -x[1])[:10]:
                print(f"    {bold(ip):<18} {cnt:>5} packets")

        if stats['dst_ips']:
            print()
            print_info("Top Destination IPs:")
            for ip, cnt in sorted(stats['dst_ips'].items(), key=lambda x: -x[1])[:10]:
                print(f"    {bold(ip):<18} {cnt:>5} packets")

        if stats['dst_ports']:
            print()
            print_info("Top Destination Ports:")
            for port, cnt in sorted(stats['dst_ports'].items(), key=lambda x: -x[1])[:10]:
                app = PORT_APPS.get(port, '')
                app_str = f" ({app})" if app else ""
                print(f"    {bold(str(port)):<8}{dim(app_str):<18} {cnt:>5} packets")

    return {
        'sniff': {
            'total_packets': stats['total'],
            'total_bytes': stats['bytes'],
            'protocols': dict(stats['protocols']),
            'top_src': dict(sorted(stats['src_ips'].items(), key=lambda x: -x[1])[:10]),
            'top_dst': dict(sorted(stats['dst_ips'].items(), key=lambda x: -x[1])[:10]),
        }
    }
