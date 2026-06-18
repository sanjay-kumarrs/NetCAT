"""
Cyber_NetCAT — File Transfer Module

TCP-based file send/receive with progress display,
integrity verification (MD5/SHA256), and optional compression.
"""

import socket
import os
import hashlib
import json
import zlib
import time

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold, progress_bar
)
from netcat_tool.utils.banner import print_module_banner
from netcat_tool.utils.validators import resolve_target


BUFFER_SIZE = 8192
HEADER_SIZE = 1024


def _calculate_hash(filepath):
    """
    Calculate MD5 and SHA256 hashes of a file.

    Args:
        filepath: Path to the file.

    Returns:
        Tuple of (md5_hex, sha256_hex).
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(BUFFER_SIZE)
            if not chunk:
                break
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def _send_file(filepath, target, port, compress=False, timeout=10):
    """
    Send a file to a receiver over TCP.

    Protocol:
        1. Connect to receiver
        2. Send JSON header (filename, size, hash, compressed)
        3. Send file data in chunks
        4. Receive confirmation

    Args:
        filepath: Path to file to send.
        target: Receiver IP address.
        port: Receiver port.
        compress: Whether to compress the file.
        timeout: Connection timeout.
    """
    if not os.path.isfile(filepath):
        print_error(f"File not found: {filepath}")
        return {'error': 'File not found'}

    filename = os.path.basename(filepath)
    filesize = os.path.getsize(filepath)
    md5_hash, sha256_hash = _calculate_hash(filepath)

    print_sub_header("Sending File")
    print_result("File", filename)
    print_result("Size", f"{filesize:,} bytes ({filesize / 1024 / 1024:.2f} MB)")
    print_result("MD5", md5_hash)
    print_result("SHA256", sha256_hash[:32] + "...")
    if compress:
        print_result("Compression", "Enabled (zlib)")
    print()

    # Read file data
    with open(filepath, 'rb') as f:
        data = f.read()

    # Compress if requested
    original_size = len(data)
    if compress:
        data = zlib.compress(data, level=6)
        print_info(f"Compressed: {original_size:,} → {len(data):,} bytes ({len(data)/original_size*100:.1f}%)")

    # Build header
    header = json.dumps({
        'filename': filename,
        'original_size': original_size,
        'transfer_size': len(data),
        'md5': md5_hash,
        'sha256': sha256_hash,
        'compressed': compress,
    }).encode()

    # Pad header to fixed size
    header = header.ljust(HEADER_SIZE, b'\x00')

    try:
        print_info(f"Connecting to {target}:{port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((target, port))
        print_success(f"Connected to {target}:{port}")

        # Send header
        sock.send(header)
        time.sleep(0.1)

        # Send file data in chunks
        total = len(data)
        sent = 0
        start_time = time.time()

        while sent < total:
            chunk = data[sent:sent + BUFFER_SIZE]
            sock.send(chunk)
            sent += len(chunk)
            progress_bar(sent, total, prefix="Uploading")

        elapsed = time.time() - start_time
        speed = total / elapsed / 1024 / 1024 if elapsed > 0 else 0

        # Wait for confirmation
        try:
            sock.settimeout(10)
            confirmation = sock.recv(256).decode('utf-8', errors='replace')
            if 'OK' in confirmation:
                print_success("Transfer confirmed by receiver!")
            else:
                print_warning(f"Receiver response: {confirmation}")
        except socket.timeout:
            print_warning("No confirmation received (transfer may still be OK)")

        sock.close()

        print()
        print(f"  {dim('─' * 40)}")
        print_result("Transfer speed", f"{speed:.2f} MB/s")
        print_result("Duration", f"{elapsed:.2f}s")
        print_success("File sent successfully!")

        return {
            'action': 'send',
            'filename': filename,
            'size': original_size,
            'transfer_size': total,
            'compressed': compress,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'speed_mbps': round(speed, 2),
            'duration': round(elapsed, 2),
        }

    except ConnectionRefusedError:
        print_error(f"Connection refused. Make sure receiver is listening on {target}:{port}")
        return {'error': 'Connection refused'}
    except socket.timeout:
        print_error("Connection timed out")
        return {'error': 'Timeout'}
    except OSError as e:
        print_error(f"Transfer error: {e}")
        return {'error': str(e)}


def _receive_file(port, output_dir='.', timeout=60):
    """
    Listen for incoming file transfers.

    Args:
        port: Port to listen on.
        output_dir: Directory to save received files.
        timeout: Listen timeout.
    """
    print_sub_header("Receiving File")
    print_info(f"Listening on 0.0.0.0:{port}")
    print_info(f"Output directory: {os.path.abspath(output_dir)}")
    print_info("Waiting for incoming transfer...")
    print()

    os.makedirs(output_dir, exist_ok=True)

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', port))
        server.listen(1)
        server.settimeout(timeout)

        client_socket, client_addr = server.accept()
        print_success(f"Connection from {client_addr[0]}:{client_addr[1]}")

        # Receive header
        header_data = b''
        while len(header_data) < HEADER_SIZE:
            chunk = client_socket.recv(HEADER_SIZE - len(header_data))
            if not chunk:
                break
            header_data += chunk

        # Parse header
        header_json = header_data.rstrip(b'\x00').decode('utf-8')
        header = json.loads(header_json)

        filename = header['filename']
        transfer_size = header['transfer_size']
        original_size = header['original_size']
        expected_md5 = header['md5']
        expected_sha256 = header['sha256']
        compressed = header.get('compressed', False)

        print_info(f"Receiving: {filename}")
        print_result("Original size", f"{original_size:,} bytes")
        print_result("Transfer size", f"{transfer_size:,} bytes")
        print_result("Compressed", str(compressed))
        print()

        # Receive file data
        data = b''
        start_time = time.time()

        while len(data) < transfer_size:
            remaining = transfer_size - len(data)
            chunk_size = min(BUFFER_SIZE, remaining)
            chunk = client_socket.recv(chunk_size)
            if not chunk:
                break
            data += chunk
            progress_bar(len(data), transfer_size, prefix="Downloading")

        elapsed = time.time() - start_time

        # Decompress if needed
        if compressed:
            print_info("Decompressing...")
            data = zlib.decompress(data)

        # Save file
        output_path = os.path.join(output_dir, filename)

        # Avoid overwriting — add suffix if exists
        if os.path.exists(output_path):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(output_path):
                output_path = os.path.join(output_dir, f"{base}_{counter}{ext}")
                counter += 1

        with open(output_path, 'wb') as f:
            f.write(data)

        # Verify integrity
        actual_md5, actual_sha256 = _calculate_hash(output_path)
        md5_ok = actual_md5 == expected_md5
        sha256_ok = actual_sha256 == expected_sha256

        # Send confirmation
        if md5_ok and sha256_ok:
            client_socket.send(b'OK: Transfer verified')
        else:
            client_socket.send(b'WARN: Hash mismatch')

        client_socket.close()

        print()
        print(f"  {dim('─' * 40)}")
        print_result("Saved to", output_path)
        print_result("MD5 verify", success("✓ PASS") if md5_ok else error("✗ FAIL"))
        print_result("SHA256 verify", success("✓ PASS") if sha256_ok else error("✗ FAIL"))

        speed = transfer_size / elapsed / 1024 / 1024 if elapsed > 0 else 0
        print_result("Speed", f"{speed:.2f} MB/s")
        print_result("Duration", f"{elapsed:.2f}s")

        if md5_ok and sha256_ok:
            print_success("File received and verified successfully!")
        else:
            print_error("WARNING: File integrity check FAILED! File may be corrupted.")

        return {
            'action': 'receive',
            'filename': filename,
            'saved_to': output_path,
            'size': len(data),
            'md5_match': md5_ok,
            'sha256_match': sha256_ok,
            'speed_mbps': round(speed, 2),
        }

    except socket.timeout:
        print_error(f"No connection received within {timeout}s timeout")
        return {'error': 'Timeout'}
    except json.JSONDecodeError:
        print_error("Invalid transfer header received")
        return {'error': 'Bad header'}
    except OSError as e:
        print_error(f"Receive error: {e}")
        return {'error': str(e)}
    finally:
        server.close()


def run_transfer(args):
    """
    Execute file transfer operations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with transfer results.
    """
    print_module_banner("File Transfer", "TCP-based file send/receive with integrity verification")

    port = args.port
    result = None

    if args.send:
        if not args.target:
            print_error("--target (-t) is required when sending files")
            return {'transfer': {'error': 'No target specified'}}

        target = resolve_target(args.target)
        result = _send_file(args.send, target, port, args.compress, args.timeout)

    elif args.receive:
        result = _receive_file(port, args.output_dir, timeout=300)

    return {'transfer': result}
