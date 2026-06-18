"""
Cyber_NetCAT — Brute Force Module

Multi-protocol authentication brute force testing for SSH, FTP,
and HTTP Basic Auth. Supports custom wordlists, threading, and
rate limiting.
"""

import socket
import ftplib
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold, critical, progress_bar
)
from netcat_tool.utils.banner import print_module_banner
from netcat_tool.utils.validators import resolve_target


def _load_wordlist(filepath):
    """
    Load passwords from a wordlist file.

    Args:
        filepath: Path to the wordlist file.

    Returns:
        List of password strings.
    """
    if not os.path.isfile(filepath):
        print_error(f"Wordlist file not found: {filepath}")
        return []

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = [line.strip() for line in f if line.strip()]

    return passwords


def _load_usernames(username_arg):
    """
    Load usernames — either a single username or from a file.

    Args:
        username_arg: Username string or path to a username file.

    Returns:
        List of username strings.
    """
    if os.path.isfile(username_arg):
        with open(username_arg, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    return [username_arg]


def _brute_ssh(target, port, username, password, timeout=5):
    """
    Attempt SSH login with given credentials.

    Args:
        target: Target IP/hostname.
        port: SSH port.
        username: SSH username.
        password: SSH password.
        timeout: Connection timeout.

    Returns:
        True if login successful, False otherwise.
    """
    try:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        client.connect(
            target, port=port, username=username, password=password,
            timeout=timeout, look_for_keys=False, allow_agent=False,
            banner_timeout=timeout
        )
        client.close()
        return True

    except ImportError:
        print_error("SSH brute force requires 'paramiko'. Install with: pip install paramiko")
        return None  # Signal to stop
    except paramiko.AuthenticationException:
        return False
    except (paramiko.SSHException, socket.error, socket.timeout, OSError):
        return False
    except Exception:
        return False


def _brute_ftp(target, port, username, password, timeout=5):
    """
    Attempt FTP login with given credentials.

    Args:
        target: Target IP/hostname.
        port: FTP port.
        username: FTP username.
        password: FTP password.
        timeout: Connection timeout.

    Returns:
        True if login successful, False otherwise.
    """
    try:
        ftp = ftplib.FTP()
        ftp.connect(target, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False
    except (socket.error, socket.timeout, OSError):
        return False
    except Exception:
        return False


def _brute_http(target, port, username, password, url='/', timeout=5):
    """
    Attempt HTTP Basic Auth login.

    Args:
        target: Target hostname/IP.
        port: HTTP port.
        username: Username.
        password: Password.
        url: URL path to authenticate against.
        timeout: Request timeout.

    Returns:
        True if login successful (non-401 response), False otherwise.
    """
    try:
        import requests
        from requests.auth import HTTPBasicAuth

        scheme = 'https' if port == 443 else 'http'
        full_url = f"{scheme}://{target}:{port}{url}"

        resp = requests.get(
            full_url,
            auth=HTTPBasicAuth(username, password),
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )

        # 401 = failed auth, anything else might be success
        return resp.status_code != 401

    except ImportError:
        # Fallback to socket-based HTTP Basic Auth
        import base64

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            request = (
                f"GET {url} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Authorization: Basic {credentials}\r\n"
                f"Connection: close\r\n\r\n"
            )
            sock.send(request.encode())

            response = sock.recv(1024).decode('utf-8', errors='replace')
            sock.close()

            return '401' not in response.split('\r\n')[0]

        except (socket.error, socket.timeout):
            return False

    except Exception:
        return False


def run_brute(args):
    """
    Execute brute force authentication testing.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with brute force results.
    """
    print_module_banner("Brute Force", "Multi-protocol authentication testing")

    target = resolve_target(args.target)
    usernames = _load_usernames(args.username)
    passwords = _load_wordlist(args.wordlist)
    delay = args.delay
    threads = args.threads
    stop_on_success = args.stop_on_success

    if not passwords:
        print_error("No passwords loaded. Check wordlist file.")
        return {'brute': {'error': 'No passwords'}}

    # Determine protocol and port
    if args.ssh:
        protocol = 'SSH'
        port = args.port or 22
        brute_func = _brute_ssh
    elif args.ftp:
        protocol = 'FTP'
        port = args.port or 21
        brute_func = _brute_ftp
    elif args.http:
        protocol = 'HTTP'
        port = args.port or 80
        brute_func = _brute_http
    else:
        print_error("No protocol specified")
        return {'brute': {'error': 'No protocol'}}

    total_attempts = len(usernames) * len(passwords)

    print_warning("⚠ Brute force testing — authorized use only!")
    print()
    print_info(f"Target: {target}:{port}")
    print_info(f"Protocol: {protocol}")
    print_info(f"Usernames: {len(usernames)} | Passwords: {len(passwords)}")
    print_info(f"Total attempts: {total_attempts:,}")
    print_info(f"Threads: {threads} | Delay: {delay}s")
    print()

    found_creds = []
    attempted = 0
    failed = 0
    lock = Lock()
    should_stop = False

    start_time = time.time()

    def attempt(username, password):
        nonlocal attempted, failed, should_stop

        if should_stop:
            return None

        if delay > 0:
            time.sleep(delay)

        if protocol == 'HTTP':
            result = brute_func(target, port, username, password, args.url, args.timeout)
        else:
            result = brute_func(target, port, username, password, args.timeout)

        with lock:
            attempted += 1

            if result is None:
                # Signal to stop (e.g., missing dependency)
                should_stop = True
                return None

            if result:
                found_creds.append((username, password))
                print(f"\r  {critical(' FOUND ')} {bold(username)}:{success(password)}")
                if stop_on_success:
                    should_stop = True
            else:
                failed += 1

            if attempted % 5 == 0 or attempted == total_attempts:
                progress_bar(attempted, total_attempts, prefix="Testing")

        return result

    # Run brute force
    print_sub_header(f"{protocol} Brute Force Attack")
    print()

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for username in usernames:
            for password in passwords:
                if should_stop:
                    break
                futures.append(executor.submit(attempt, username, password))
            if should_stop:
                break

        for future in as_completed(futures):
            if should_stop:
                break
            try:
                future.result()
            except Exception:
                pass

    elapsed = time.time() - start_time

    # Results
    print()
    print()
    print(f"  {dim('─' * 50)}")
    print_result("Protocol", protocol)
    print_result("Target", f"{target}:{port}")
    print_result("Attempts", f"{attempted:,} / {total_attempts:,}")
    print_result("Duration", f"{elapsed:.1f}s")
    print_result("Rate", f"{attempted / elapsed:.1f} attempts/sec" if elapsed > 0 else "N/A")

    if found_creds:
        print()
        print_success(f"Found {len(found_creds)} valid credential(s):")
        for user, pw in found_creds:
            print(f"    {success('●')} {bold(user)} : {success(pw)}")
    else:
        print()
        print_warning("No valid credentials found.")

    return {
        'brute': {
            'protocol': protocol,
            'target': f"{target}:{port}",
            'attempts': attempted,
            'found': [{'username': u, 'password': p} for u, p in found_creds],
            'duration': round(elapsed, 2),
        }
    }
