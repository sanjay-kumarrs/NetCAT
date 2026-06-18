"""
Cyber_NetCAT — Packet Crafter Module

Create and send custom TCP, UDP, and ICMP packets with configurable
flags, payloads, source spoofing, and flood capabilities.
"""

import socket
import struct
import random
import time
import os

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold
)
from netcat_tool.utils.banner import print_module_banner
from netcat_tool.utils.validators import resolve_target


# TCP Flag constants
TCP_FLAGS = {
    'FIN': 0x01,
    'SYN': 0x02,
    'RST': 0x04,
    'PSH': 0x08,
    'ACK': 0x10,
    'URG': 0x20,
    'ECE': 0x40,
    'CWR': 0x80,
}


def _checksum(data):
    """Calculate the Internet checksum for packet data."""
    if len(data) % 2:
        data += b'\x00'

    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i + 1]
        s += w

    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return (~s) & 0xffff


def _parse_flags(flags_str):
    """Parse flag string (e.g., 'SYN,ACK') into flag byte."""
    flag_byte = 0
    for flag in flags_str.upper().split(','):
        flag = flag.strip()
        if flag in TCP_FLAGS:
            flag_byte |= TCP_FLAGS[flag]
        else:
            print_warning(f"Unknown TCP flag: {flag}")
    return flag_byte


def _build_ip_header(src_ip, dst_ip, protocol, payload_len):
    """
    Build a raw IP header.

    Args:
        src_ip: Source IP address string.
        dst_ip: Destination IP address string.
        protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP).
        payload_len: Length of the payload.

    Returns:
        Bytes of the IP header.
    """
    version = 4
    ihl = 5
    tos = 0
    total_length = 20 + payload_len
    identification = random.randint(1, 65535)
    frag_offset = 0
    ttl = 64
    checksum = 0

    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)

    header = struct.pack('!BBHHHBBH4s4s',
                         (version << 4) + ihl, tos, total_length,
                         identification, frag_offset,
                         ttl, protocol, checksum, src, dst)

    # Calculate checksum
    checksum = _checksum(header)
    header = struct.pack('!BBHHHBBH4s4s',
                         (version << 4) + ihl, tos, total_length,
                         identification, frag_offset,
                         ttl, protocol, checksum, src, dst)

    return header


def _build_tcp_packet(src_ip, dst_ip, src_port, dst_port, flags, seq=0, ack=0, data=b''):
    """
    Build a TCP packet.

    Args:
        src_ip: Source IP.
        dst_ip: Destination IP.
        src_port: Source port.
        dst_port: Destination port.
        flags: TCP flag byte.
        seq: Sequence number.
        ack: Acknowledgment number.
        data: Payload data.

    Returns:
        Bytes of the complete TCP segment.
    """
    offset = 5  # 20 bytes, no options
    offset_flags = (offset << 4) | 0
    window = 65535
    checksum = 0
    urg_ptr = 0

    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, ack,
                             offset_flags, flags, window, checksum, urg_ptr)

    # Pseudo header for checksum calculation
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    proto = 6  # TCP
    tcp_length = len(tcp_header) + len(data)

    pseudo = struct.pack('!4s4sBBH', src, dst, 0, proto, tcp_length)
    checksum = _checksum(pseudo + tcp_header + data)

    tcp_header = struct.pack('!HHIIBBHHH',
                             src_port, dst_port, seq, ack,
                             offset_flags, flags, window, checksum, urg_ptr)

    return tcp_header + data


def _build_udp_packet(src_port, dst_port, data=b''):
    """
    Build a UDP datagram.

    Args:
        src_port: Source port.
        dst_port: Destination port.
        data: Payload data.

    Returns:
        Bytes of the UDP datagram.
    """
    length = 8 + len(data)
    checksum = 0
    header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
    return header + data


def _build_icmp_packet(icmp_type=8, code=0, data=b''):
    """
    Build an ICMP packet.

    Args:
        icmp_type: ICMP type (8 = echo request).
        code: ICMP code.
        data: Payload data.

    Returns:
        Bytes of the ICMP packet.
    """
    identifier = os.getpid() & 0xFFFF
    sequence = 1
    checksum = 0

    header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)
    checksum = _checksum(header + data)
    header = struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)

    return header + data


def _send_tcp(target, port, flags_str, data, count, src_ip, timeout, flood=False):
    """
    Send custom TCP packets.

    Args:
        target: Target IP.
        port: Target port.
        flags_str: TCP flags string.
        data: Payload data.
        count: Number of packets.
        src_ip: Source IP (None for real IP).
        timeout: Socket timeout.
        flood: If True, send continuously.

    Returns:
        Dictionary with send results.
    """
    flag_byte = _parse_flags(flags_str)
    flags_display = flags_str.upper()
    sent = 0
    errors = 0
    responses = 0

    # Determine if we need raw sockets
    use_raw = src_ip is not None

    if use_raw:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(timeout)
        except PermissionError:
            print_error("Raw sockets require administrator/root privileges.")
            print_info("Falling back to standard TCP socket (no IP spoofing)...")
            use_raw = False
        except OSError as e:
            print_error(f"Cannot create raw socket: {e}")
            use_raw = False

    if not use_raw:
        # Standard socket approach
        src_port = random.randint(40000, 65000)
        payload = data.encode() if isinstance(data, str) else data

        target_count = count if not flood else float('inf')
        i = 0

        while i < target_count:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                if flag_byte == TCP_FLAGS['SYN']:
                    # SYN scan - just connect
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        if payload:
                            sock.send(payload)
                        responses += 1
                    sent += 1
                else:
                    sock.connect((target, port))
                    if payload:
                        sock.send(payload)
                    sent += 1
                    responses += 1

                sock.close()

            except (socket.timeout, ConnectionRefusedError, OSError):
                sent += 1
                errors += 1

            i += 1

            if flood:
                if i % 100 == 0:
                    print(f"\r  {info('[~]')} Sent: {sent} | Responses: {responses} | Errors: {errors}", end='')
            elif i % 10 == 0 or i == count:
                print(f"\r  {info('[~]')} Sent: {sent}/{count} | Responses: {responses}", end='')

        print()

    else:
        # Raw socket approach with IP spoofing
        local_ip = src_ip
        src_port = random.randint(40000, 65000)
        payload = data.encode() if isinstance(data, str) else data

        for i in range(count):
            try:
                seq = random.randint(0, 0xFFFFFFFF)
                tcp_packet = _build_tcp_packet(
                    local_ip, target, src_port, port, flag_byte,
                    seq=seq, data=payload
                )
                ip_header = _build_ip_header(local_ip, target, 6, len(tcp_packet))

                sock.sendto(ip_header + tcp_packet, (target, port))
                sent += 1

            except Exception as e:
                errors += 1

            if (i + 1) % 10 == 0 or (i + 1) == count:
                print(f"\r  {info('[~]')} Sent: {sent}/{count} | Errors: {errors}", end='')

        print()
        sock.close()

    return {
        'type': 'TCP',
        'flags': flags_display,
        'sent': sent,
        'responses': responses,
        'errors': errors,
    }


def _send_udp(target, port, data, count, timeout, flood=False):
    """Send custom UDP packets."""
    sent = 0
    errors = 0
    payload = data.encode() if isinstance(data, str) else data
    if not payload:
        payload = b'\x00'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    target_count = count if not flood else float('inf')
    i = 0

    while i < target_count:
        try:
            sock.sendto(payload, (target, port))
            sent += 1
        except Exception:
            errors += 1

        i += 1

        if i % 100 == 0 or i == count:
            print(f"\r  {info('[~]')} Sent: {sent} | Errors: {errors}", end='')

        if flood and i % 1000 == 0:
            print(f"\r  {info('[~]')} Flooding — Sent: {sent} | Errors: {errors}", end='')

    print()
    sock.close()

    return {'type': 'UDP', 'sent': sent, 'errors': errors}


def _send_icmp(target, data, count, timeout):
    """Send custom ICMP packets."""
    sent = 0
    errors = 0
    responses = 0
    payload = data.encode() if isinstance(data, str) else data
    if not payload:
        payload = b'Cyber_NetCAT_PING' + bytes(range(48))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
    except PermissionError:
        print_error("ICMP requires administrator/root privileges.")
        return {'type': 'ICMP', 'sent': 0, 'errors': 1, 'responses': 0}
    except OSError as e:
        print_error(f"Cannot create ICMP socket: {e}")
        return {'type': 'ICMP', 'sent': 0, 'errors': 1, 'responses': 0}

    for i in range(count):
        try:
            packet = _build_icmp_packet(icmp_type=8, code=0, data=payload)
            sock.sendto(packet, (target, 0))
            sent += 1

            try:
                resp, addr = sock.recvfrom(1024)
                responses += 1
            except socket.timeout:
                pass

        except Exception:
            errors += 1

        if (i + 1) % 10 == 0 or (i + 1) == count:
            print(f"\r  {info('[~]')} Sent: {sent}/{count} | Responses: {responses} | Errors: {errors}", end='')

    print()
    sock.close()

    return {'type': 'ICMP', 'sent': sent, 'errors': errors, 'responses': responses}


def run_craft(args):
    """
    Execute packet crafting operations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with crafting results.
    """
    print_module_banner("Packet Crafter", "Custom TCP/UDP/ICMP packet construction and sending")

    target = resolve_target(args.target)
    port = args.port
    data = args.data
    count = args.count
    timeout = args.timeout

    print_info(f"Target: {target}:{port}")

    if args.spoof:
        print_warning(f"Source IP spoofing: {args.spoof}")
    if args.flood:
        print_warning("⚠ FLOOD MODE ENABLED — Press Ctrl+C to stop")
        count = 999999999  # Effectively infinite

    print()
    result = None

    if args.tcp or (not args.udp and not args.icmp):
        # TCP (default)
        print_sub_header(f"Sending TCP [{args.flags}] → {target}:{port}")
        print_info(f"Packets: {'∞ (flood)' if args.flood else count} | Payload: {len(data)} bytes")
        print()
        result = _send_tcp(target, port, args.flags, data, count, args.spoof, timeout, args.flood)

    elif args.udp:
        print_sub_header(f"Sending UDP → {target}:{port}")
        print_info(f"Packets: {'∞ (flood)' if args.flood else count} | Payload: {len(data)} bytes")
        print()
        result = _send_udp(target, port, data, count, timeout, args.flood)

    elif args.icmp:
        print_sub_header(f"Sending ICMP → {target}")
        print_info(f"Packets: {count} | Payload: {len(data)} bytes")
        print()
        result = _send_icmp(target, data, count, timeout)

    # Display results
    if result:
        print()
        print(f"  {dim('─' * 40)}")
        print_result("Protocol", result['type'])
        if 'flags' in result:
            print_result("Flags", result['flags'])
        print_result("Sent", str(result['sent']))
        if 'responses' in result:
            print_result("Responses", str(result['responses']))
        print_result("Errors", str(result['errors']))

    return {'craft': result}
