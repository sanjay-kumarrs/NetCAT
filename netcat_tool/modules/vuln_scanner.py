"""
Cyber_NetCAT — Vulnerability Scanner Module

Port-based vulnerability mapping, SSL/TLS analysis, HTTP security
header checks, known CVE references, and default credential detection.
"""

import socket
import ssl
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold, critical
)
from netcat_tool.utils.banner import print_module_banner
from netcat_tool.utils.validators import parse_ports, resolve_target


# ─── Built-in CVE/Vulnerability Reference Database ───────────────────
VULN_DB = {
    21: {
        'service': 'FTP',
        'risks': ['Anonymous FTP access', 'Cleartext authentication', 'Directory traversal'],
        'cves': ['CVE-2010-4221 (ProFTPD)', 'CVE-2015-3306 (ProFTPD mod_copy)', 'CVE-2011-2523 (vsftpd backdoor)'],
        'severity': 'HIGH',
    },
    22: {
        'service': 'SSH',
        'risks': ['Brute force attacks', 'Weak key exchange algorithms', 'Outdated SSH versions'],
        'cves': ['CVE-2016-0777 (OpenSSH roaming)', 'CVE-2018-15473 (User enumeration)', 'CVE-2023-38408 (Agent forwarding)'],
        'severity': 'MEDIUM',
    },
    23: {
        'service': 'Telnet',
        'risks': ['Cleartext communication', 'No encryption', 'Credential sniffing'],
        'cves': ['CVE-2020-10188 (Telnetd overflow)', 'CVE-2022-29154'],
        'severity': 'CRITICAL',
    },
    25: {
        'service': 'SMTP',
        'risks': ['Open relay', 'Email spoofing', 'VRFY user enumeration'],
        'cves': ['CVE-2019-15846 (Exim RCE)', 'CVE-2021-22214 (Postfix)', 'CVE-2020-28018 (Exim UAF)'],
        'severity': 'HIGH',
    },
    53: {
        'service': 'DNS',
        'risks': ['DNS amplification', 'Zone transfer', 'Cache poisoning'],
        'cves': ['CVE-2020-1350 (SigRed Windows DNS)', 'CVE-2008-1447 (Kaminsky)', 'CVE-2021-25216 (BIND)'],
        'severity': 'HIGH',
    },
    80: {
        'service': 'HTTP',
        'risks': ['Unencrypted traffic', 'XSS', 'SQL injection', 'Directory listing'],
        'cves': ['CVE-2021-41773 (Apache path traversal)', 'CVE-2017-5638 (Struts RCE)', 'CVE-2019-0211 (Apache priv-esc)'],
        'severity': 'MEDIUM',
    },
    110: {
        'service': 'POP3',
        'risks': ['Cleartext credentials', 'Brute force'],
        'cves': ['CVE-2003-0264 (Stripping attack)'],
        'severity': 'HIGH',
    },
    135: {
        'service': 'MSRPC',
        'risks': ['Remote code execution', 'Information disclosure'],
        'cves': ['CVE-2003-0352 (MS03-026 DCOM)', 'CVE-2008-4250 (MS08-067)'],
        'severity': 'CRITICAL',
    },
    139: {
        'service': 'NetBIOS',
        'risks': ['Session hijacking', 'Information leakage', 'Null sessions'],
        'cves': ['CVE-2017-0143 (EternalBlue)', 'CVE-2020-0796 (SMBGhost)'],
        'severity': 'CRITICAL',
    },
    443: {
        'service': 'HTTPS',
        'risks': ['Weak cipher suites', 'Expired certificates', 'Protocol downgrade'],
        'cves': ['CVE-2014-0160 (Heartbleed)', 'CVE-2014-3566 (POODLE)', 'CVE-2015-0204 (FREAK)'],
        'severity': 'MEDIUM',
    },
    445: {
        'service': 'SMB',
        'risks': ['EternalBlue', 'Ransomware propagation', 'Null sessions'],
        'cves': ['CVE-2017-0144 (EternalBlue/WannaCry)', 'CVE-2020-0796 (SMBGhost)', 'CVE-2020-1472 (Zerologon)'],
        'severity': 'CRITICAL',
    },
    1433: {
        'service': 'MSSQL',
        'risks': ['Default sa account', 'SQL injection', 'xp_cmdshell'],
        'cves': ['CVE-2020-0618 (SSRS RCE)', 'CVE-2019-1068'],
        'severity': 'HIGH',
    },
    3306: {
        'service': 'MySQL',
        'risks': ['Default credentials', 'Remote root login', 'SQL injection'],
        'cves': ['CVE-2012-2122 (Auth bypass)', 'CVE-2016-6662 (Config manipulation)'],
        'severity': 'HIGH',
    },
    3389: {
        'service': 'RDP',
        'risks': ['BlueKeep', 'Brute force', 'NLA bypass'],
        'cves': ['CVE-2019-0708 (BlueKeep)', 'CVE-2019-1181 (DejaBlue)', 'CVE-2019-1182'],
        'severity': 'CRITICAL',
    },
    5432: {
        'service': 'PostgreSQL',
        'risks': ['Default credentials', 'Remote code execution'],
        'cves': ['CVE-2019-9193 (COPY FROM PROGRAM)', 'CVE-2023-5868'],
        'severity': 'HIGH',
    },
    6379: {
        'service': 'Redis',
        'risks': ['No authentication', 'Remote code execution', 'Data exfiltration'],
        'cves': ['CVE-2022-0543 (Lua sandbox escape)', 'CVE-2021-32761 (Integer overflow)'],
        'severity': 'CRITICAL',
    },
    8080: {
        'service': 'HTTP Proxy',
        'risks': ['Open proxy', 'Management interface exposure', 'Default credentials'],
        'cves': ['CVE-2020-1938 (Ghostcat/Tomcat AJP)', 'CVE-2017-12617 (Tomcat PUT)'],
        'severity': 'HIGH',
    },
    27017: {
        'service': 'MongoDB',
        'risks': ['No authentication', 'Data exposure', 'Remote access'],
        'cves': ['CVE-2013-1892', 'CVE-2015-7882 (Auth bypass)'],
        'severity': 'CRITICAL',
    },
}

# Default credentials to check
DEFAULT_CREDS = {
    'FTP': [('anonymous', 'anonymous'), ('admin', 'admin'), ('ftp', 'ftp')],
    'SSH': [('root', 'root'), ('admin', 'admin'), ('admin', 'password')],
    'MySQL': [('root', ''), ('root', 'root'), ('admin', 'admin')],
    'PostgreSQL': [('postgres', 'postgres'), ('admin', 'admin')],
    'Redis': [('', '')],  # No auth check
    'MongoDB': [('', '')],
}

# HTTP security headers to check
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'present': 'HSTS enabled — forces HTTPS connections',
        'missing': 'HSTS not set — vulnerable to protocol downgrade attacks',
        'severity': 'HIGH',
    },
    'Content-Security-Policy': {
        'present': 'CSP set — helps prevent XSS and injection attacks',
        'missing': 'CSP not set — vulnerable to XSS and data injection',
        'severity': 'MEDIUM',
    },
    'X-Frame-Options': {
        'present': 'X-Frame-Options set — clickjacking protection',
        'missing': 'X-Frame-Options not set — vulnerable to clickjacking',
        'severity': 'MEDIUM',
    },
    'X-Content-Type-Options': {
        'present': 'X-Content-Type-Options set — MIME sniffing prevention',
        'missing': 'X-Content-Type-Options not set — MIME sniffing possible',
        'severity': 'LOW',
    },
    'X-XSS-Protection': {
        'present': 'X-XSS-Protection set — browser XSS filter enabled',
        'missing': 'X-XSS-Protection not set — browser XSS filter may be off',
        'severity': 'LOW',
    },
    'Referrer-Policy': {
        'present': 'Referrer-Policy set — controls referrer information',
        'missing': 'Referrer-Policy not set — full referrer may be leaked',
        'severity': 'LOW',
    },
    'Permissions-Policy': {
        'present': 'Permissions-Policy set — controls browser features',
        'missing': 'Permissions-Policy not set — all browser features allowed',
        'severity': 'LOW',
    },
    'X-Permitted-Cross-Domain-Policies': {
        'present': 'Cross-domain policy restricted',
        'missing': 'Cross-domain policy not restricted',
        'severity': 'LOW',
    },
}

SEVERITY_COLORS = {
    'CRITICAL': lambda t: critical(f" {t} "),
    'HIGH': lambda t: error(t),
    'MEDIUM': lambda t: warning(t),
    'LOW': lambda t: info(t),
    'INFO': lambda t: dim(t),
}


def _check_ssl(target, port=443, timeout=5):
    """
    Analyze SSL/TLS configuration of a target.

    Args:
        target: Target hostname or IP.
        port: HTTPS port.
        timeout: Connection timeout.

    Returns:
        Dictionary with SSL analysis results.
    """
    result = {
        'port': port,
        'ssl_enabled': False,
        'issues': [],
        'info': [],
    }

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                result['ssl_enabled'] = True
                result['protocol'] = ssock.version()
                result['cipher'] = ssock.cipher()

                # Get certificate
                cert = ssock.getpeercert(binary_form=False)
                if cert:
                    result['cert'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'not_before': cert.get('notBefore', 'N/A'),
                        'not_after': cert.get('notAfter', 'N/A'),
                        'serial': cert.get('serialNumber', 'N/A'),
                        'san': [x[1] for x in cert.get('subjectAltName', [])],
                    }

                    # Check expiration
                    try:
                        expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expires < datetime.now():
                            result['issues'].append(('CRITICAL', 'Certificate has EXPIRED'))
                        elif (expires - datetime.now()).days < 30:
                            result['issues'].append(('HIGH', f'Certificate expires in {(expires - datetime.now()).days} days'))
                        else:
                            result['info'].append(f'Certificate expires: {cert["notAfter"]}')
                    except Exception:
                        pass

                # Check protocol version
                version = ssock.version()
                if version in ('SSLv2', 'SSLv3'):
                    result['issues'].append(('CRITICAL', f'Insecure protocol: {version}'))
                elif version == 'TLSv1':
                    result['issues'].append(('HIGH', f'Deprecated protocol: {version}'))
                elif version == 'TLSv1.1':
                    result['issues'].append(('MEDIUM', f'Deprecated protocol: {version}'))
                else:
                    result['info'].append(f'Protocol: {version}')

                # Check cipher strength
                cipher_name, cipher_proto, cipher_bits = ssock.cipher()
                if cipher_bits and cipher_bits < 128:
                    result['issues'].append(('HIGH', f'Weak cipher: {cipher_name} ({cipher_bits}-bit)'))
                elif 'RC4' in cipher_name or 'DES' in cipher_name or 'NULL' in cipher_name:
                    result['issues'].append(('HIGH', f'Weak cipher: {cipher_name}'))
                else:
                    result['info'].append(f'Cipher: {cipher_name} ({cipher_bits}-bit)')

    except ssl.SSLError as e:
        result['issues'].append(('HIGH', f'SSL Error: {e}'))
    except ConnectionRefusedError:
        result['issues'].append(('INFO', f'Port {port} is closed'))
    except socket.timeout:
        result['issues'].append(('INFO', f'Connection timed out on port {port}'))
    except Exception as e:
        result['issues'].append(('INFO', f'Error: {e}'))

    return result


def _check_http_headers(target, port=80, use_ssl=False, timeout=5):
    """
    Analyze HTTP security headers.

    Args:
        target: Target hostname or IP.
        port: HTTP port.
        use_ssl: Whether to use HTTPS.
        timeout: Timeout.

    Returns:
        Dictionary with header analysis results.
    """
    result = {'headers': {}, 'missing': [], 'present': [], 'server': None}

    try:
        import requests
        scheme = 'https' if use_ssl else 'http'
        url = f"{scheme}://{target}:{port}/"

        resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        headers = dict(resp.headers)
        result['status_code'] = resp.status_code
        result['headers'] = headers
        result['server'] = headers.get('Server', 'Not disclosed')

        # Check each security header
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name.lower() in {k.lower(): k for k in headers}:
                # Find actual header value (case-insensitive)
                for k, v in headers.items():
                    if k.lower() == header_name.lower():
                        result['present'].append({
                            'header': header_name,
                            'value': v,
                            'message': header_info['present'],
                        })
                        break
            else:
                result['missing'].append({
                    'header': header_name,
                    'message': header_info['missing'],
                    'severity': header_info['severity'],
                })

        # Check for information disclosure headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for ih in info_headers:
            if ih in headers:
                result['missing'].append({
                    'header': ih,
                    'message': f'{ih} header discloses: {headers[ih]}',
                    'severity': 'LOW',
                })

    except ImportError:
        # Fallback without requests
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=target)

            request = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
            sock.send(request.encode())

            response = sock.recv(4096).decode('utf-8', errors='replace')
            sock.close()

            for line in response.splitlines():
                if ':' in line:
                    key, _, value = line.partition(':')
                    result['headers'][key.strip()] = value.strip()

            # Check security headers
            for header_name, header_info in SECURITY_HEADERS.items():
                found = False
                for k in result['headers']:
                    if k.lower() == header_name.lower():
                        found = True
                        result['present'].append({
                            'header': header_name,
                            'value': result['headers'][k],
                            'message': header_info['present'],
                        })
                        break
                if not found:
                    result['missing'].append({
                        'header': header_name,
                        'message': header_info['missing'],
                        'severity': header_info['severity'],
                    })

        except Exception as e:
            result['error'] = str(e)

    except Exception as e:
        result['error'] = str(e)

    return result


def _check_port_vulns(target, ports, timeout=2):
    """
    Check open ports against the vulnerability database.

    Args:
        target: Target IP.
        ports: List of port numbers.
        timeout: Connection timeout.

    Returns:
        List of vulnerability findings.
    """
    findings = []

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0 and port in VULN_DB:
                return VULN_DB[port]
            return None
        except socket.error:
            return None

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_port, p): p for p in ports}
        for future in as_completed(futures):
            port = futures[future]
            vuln = future.result()
            if vuln:
                findings.append({'port': port, **vuln})

    return findings


def run_vuln_scan(args):
    """
    Execute vulnerability scanning operations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with vulnerability scan results.
    """
    print_module_banner("Vulnerability Scanner", "CVE mapping, SSL/TLS analysis, HTTP header checks")

    target = resolve_target(args.target)
    results = {'target': target, 'findings': []}

    run_ssl = args.ssl_check or args.full
    run_headers = args.headers or args.full
    run_cve = args.cve or args.full

    if not any([run_ssl, run_headers, run_cve]):
        # Default: run CVE check
        run_cve = True

    print_info(f"Target: {target} ({args.target})")

    # Port-based vulnerability check
    if run_cve:
        print_sub_header("Port-Based Vulnerability Assessment")
        ports = parse_ports(args.ports)
        print_info(f"Checking {len(ports)} ports against CVE database...")
        print()

        findings = _check_port_vulns(target, ports, args.timeout)

        if findings:
            findings.sort(key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['severity'], 4))

            for finding in findings:
                severity = finding['severity']
                sev_color = SEVERITY_COLORS.get(severity, dim)
                print(f"  {sev_color(f'[{severity}]'):<20} Port {bold(str(finding['port']))}/tcp — {info(finding['service'])}")

                for risk in finding['risks']:
                    print(f"  {'':20} {warning('⚠')} {risk}")

                for cve in finding.get('cves', []):
                    print(f"  {'':20} {dim('CVE:')} {cve}")
                print()

            results['findings'] = findings
        else:
            print_success("No known vulnerabilities found for open ports.")

    # SSL/TLS check
    if run_ssl:
        print_sub_header("SSL/TLS Configuration Analysis")

        # Check common SSL ports
        ssl_ports = [443, 8443, 465, 993, 995, 636]
        ports_to_check = parse_ports(args.ports)
        ssl_ports_to_check = [p for p in ssl_ports if p in ports_to_check] or [443]

        ssl_results = []
        for port in ssl_ports_to_check:
            print_info(f"Checking SSL/TLS on port {port}...")
            ssl_result = _check_ssl(target, port, args.timeout)
            ssl_results.append(ssl_result)

            if ssl_result['ssl_enabled']:
                print_success(f"SSL/TLS active on port {port}")

                for sev, issue in ssl_result['issues']:
                    sev_color = SEVERITY_COLORS.get(sev, dim)
                    print(f"    {sev_color(f'[{sev}]'):<20} {issue}")

                for inf in ssl_result['info']:
                    print(f"    {dim('[INFO]'):<20} {inf}")

                if ssl_result.get('cert'):
                    cert = ssl_result['cert']
                    cn = cert.get('subject', {}).get('commonName', 'N/A')
                    issuer_cn = cert.get('issuer', {}).get('commonName', 'N/A')
                    print(f"    {dim('Subject CN:')} {cn}")
                    print(f"    {dim('Issuer CN:')} {issuer_cn}")
                    if cert.get('san'):
                        print(f"    {dim('SANs:')} {', '.join(cert['san'][:5])}")
                print()
            else:
                if ssl_result['issues']:
                    for sev, issue in ssl_result['issues']:
                        print(f"    {dim(f'[{sev}]')} {issue}")

        results['ssl'] = ssl_results

    # HTTP header check
    if run_headers:
        print_sub_header("HTTP Security Headers Analysis")

        for use_ssl in [False, True]:
            port = 443 if use_ssl else 80
            scheme = "HTTPS" if use_ssl else "HTTP"
            print_info(f"Checking {scheme} headers on port {port}...")

            header_result = _check_http_headers(target, port, use_ssl, args.timeout)

            if header_result.get('error'):
                print_warning(f"Could not connect: {header_result['error']}")
                continue

            if header_result.get('server'):
                print_result("Server", header_result['server'])

            print()

            # Present headers (good)
            if header_result['present']:
                for h in header_result['present']:
                    print(f"    {success('✓')} {bold(h['header']):<35} {dim(h['message'])}")

            # Missing headers (bad)
            if header_result['missing']:
                for h in header_result['missing']:
                    sev = h.get('severity', 'LOW')
                    sev_color = SEVERITY_COLORS.get(sev, dim)
                    print(f"    {error('✗')} {bold(h['header']):<35} {sev_color(f'[{sev}]')} {h['message']}")

            print()
            results[f'headers_{scheme.lower()}'] = header_result

    # Summary
    print(f"  {dim('─' * 60)}")
    total_vulns = len(results.get('findings', []))
    critical_count = sum(1 for f in results.get('findings', []) if f['severity'] == 'CRITICAL')
    high_count = sum(1 for f in results.get('findings', []) if f['severity'] == 'HIGH')

    print_result("Total findings", str(total_vulns))
    if critical_count:
        print_result("Critical", critical(f" {critical_count} "))
    if high_count:
        print_result("High", error(str(high_count)))

    return {'vulnscan': results}
