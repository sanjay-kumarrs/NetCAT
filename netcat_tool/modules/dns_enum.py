"""
Cyber_NetCAT — DNS Enumeration Module

Performs DNS record lookups, subdomain brute-force enumeration,
zone transfer attempts, and reverse DNS lookups.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from netcat_tool.utils.colors import (
    print_sub_header, print_info, print_success, print_error,
    print_warning, print_result, success, error, warning,
    info, dim, bold, progress_bar
)
from netcat_tool.utils.banner import print_module_banner


# Built-in subdomain wordlist for enumeration
DEFAULT_SUBDOMAINS = [
    'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'staging', 'test',
    'api', 'app', 'cdn', 'cloud', 'cpanel', 'dashboard', 'db', 'demo',
    'dns', 'docs', 'email', 'files', 'forum', 'git', 'gitlab', 'help',
    'host', 'imap', 'intranet', 'jenkins', 'jira', 'ldap', 'login',
    'manage', 'monitor', 'mysql', 'ns', 'ns1', 'ns2', 'ns3', 'panel',
    'pop', 'portal', 'proxy', 'redis', 'remote', 'repo', 'search',
    'secure', 'server', 'shop', 'smtp', 'sql', 'ssh', 'ssl', 'stage',
    'status', 'store', 'support', 'svn', 'vpn', 'webmail', 'wiki',
    'www2', 'beta', 'alpha', 'gateway', 'mx', 'mx1', 'mx2', 'backup',
    'ci', 'internal', 'lab', 'legacy', 'media', 'mobile', 'office',
    'old', 'ops', 'origin', 'pma', 'preview', 'prod', 'production',
    'qa', 'sandbox', 'sentry', 'service', 'sso', 'static', 'stats',
    'storage', 'sys', 'vault', 'web', 'ws', 'autodiscover', 'exchange',
    'lyncdiscover', 'owa', 'relay', 'router', 'sip', 'firewall',
]


def _dns_lookup(domain, record_type, server=None):
    """
    Perform a DNS lookup using dnspython.

    Args:
        domain: Domain name to look up.
        record_type: DNS record type (A, AAAA, MX, NS, TXT, CNAME, SOA).
        server: Optional custom DNS server.

    Returns:
        List of record strings.
    """
    try:
        import dns.resolver
        import dns.exception

        resolver = dns.resolver.Resolver()
        if server:
            resolver.nameservers = [socket.gethostbyname(server)]

        resolver.timeout = 5
        resolver.lifetime = 10

        answers = resolver.resolve(domain, record_type)
        records = []

        for rdata in answers:
            if record_type == 'MX':
                records.append(f"{rdata.preference} {rdata.exchange}")
            elif record_type == 'SOA':
                records.append(
                    f"mname={rdata.mname} rname={rdata.rname} "
                    f"serial={rdata.serial} refresh={rdata.refresh} "
                    f"retry={rdata.retry} expire={rdata.expire} "
                    f"minimum={rdata.minimum}"
                )
            elif record_type == 'TXT':
                for txt_string in rdata.strings:
                    records.append(txt_string.decode('utf-8', errors='replace'))
            else:
                records.append(str(rdata))

        return records

    except ImportError:
        # Fallback to socket if dnspython is not available
        if record_type == 'A':
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                return list(set(ip[4][0] for ip in ips))
            except socket.gaierror:
                return []
        elif record_type == 'AAAA':
            try:
                ips = socket.getaddrinfo(domain, None, socket.AF_INET6)
                return list(set(ip[4][0] for ip in ips))
            except socket.gaierror:
                return []
        else:
            print_warning(f"Install 'dnspython' for {record_type} record lookups: pip install dnspython")
            return []

    except Exception as e:
        return []


def _zone_transfer(domain, server=None):
    """
    Attempt a DNS zone transfer (AXFR).

    Args:
        domain: Target domain.
        server: DNS server to query. If None, uses domain's NS records.

    Returns:
        List of zone transfer records, or empty list if failed.
    """
    try:
        import dns.zone
        import dns.query
        import dns.resolver

        # Get NS servers if not specified
        if server:
            ns_servers = [server]
        else:
            ns_records = _dns_lookup(domain, 'NS')
            ns_servers = [str(ns).rstrip('.') for ns in ns_records]

        all_records = []

        for ns in ns_servers:
            try:
                ns_ip = socket.gethostbyname(ns)
                print_info(f"Attempting zone transfer from {ns} ({ns_ip})...")

                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))

                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            record = f"{name}.{domain}  {rdataset.rdtype.name}  {rdata}"
                            all_records.append(record)

                if all_records:
                    print_success(f"Zone transfer successful from {ns}!")
                    return all_records

            except Exception as e:
                print_warning(f"Zone transfer failed from {ns}: {e}")

        return all_records

    except ImportError:
        print_warning("Install 'dnspython' for zone transfer: pip install dnspython")
        return []


def _reverse_dns(ip_address):
    """
    Perform reverse DNS lookup.

    Args:
        ip_address: IP address to look up.

    Returns:
        Hostname string, or None.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def _enumerate_subdomains(domain, wordlist=None, threads=20):
    """
    Enumerate subdomains via brute force DNS lookups.

    Args:
        domain: Base domain.
        wordlist: Optional file path to subdomain wordlist.
        threads: Number of concurrent threads.

    Returns:
        List of dictionaries with subdomain info.
    """
    # Load wordlist
    if wordlist:
        try:
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                subdomains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print_error(f"Wordlist file not found: {wordlist}")
            return []
    else:
        subdomains = DEFAULT_SUBDOMAINS

    found = []
    total = len(subdomains)
    checked = 0

    def check_subdomain(sub):
        nonlocal checked
        fqdn = f"{sub}.{domain}"
        try:
            ips = socket.getaddrinfo(fqdn, None, socket.AF_INET)
            ip_list = list(set(ip[4][0] for ip in ips))
            checked += 1
            progress_bar(checked, total, prefix="Enumerating")
            if ip_list:
                return {'subdomain': fqdn, 'ips': ip_list}
        except socket.gaierror:
            checked += 1
            progress_bar(checked, total, prefix="Enumerating")
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    print()  # newline after progress bar
    return found


def run_dns_enum(args):
    """
    Execute DNS enumeration operations.

    Args:
        args: Parsed CLI arguments.

    Returns:
        Dictionary with DNS enumeration results.
    """
    print_module_banner("DNS Enumeration", "DNS record lookup, subdomain brute force, zone transfer")

    domain = args.domain
    record_types = [rt.strip().upper() for rt in args.record_types.split(',')]
    results = {'domain': domain}

    print_info(f"Target domain: {domain}")

    # Reverse DNS lookup
    if args.reverse:
        print_sub_header("Reverse DNS Lookup")
        hostname = _reverse_dns(args.reverse)
        if hostname:
            print_success(f"{args.reverse} → {hostname}")
            results['reverse_dns'] = {args.reverse: hostname}
        else:
            print_warning(f"No PTR record found for {args.reverse}")
            results['reverse_dns'] = {args.reverse: None}

    # Standard DNS record lookups
    print_sub_header("DNS Record Lookups")
    print_info(f"Record types: {', '.join(record_types)}")
    print()

    dns_records = {}
    for rtype in record_types:
        records = _dns_lookup(domain, rtype, args.server)
        dns_records[rtype] = records

        if records:
            print(f"  {success('✓')} {bold(rtype):>8}  ", end="")
            for i, record in enumerate(records):
                if i > 0:
                    print(f"  {'':>10}  ", end="")
                print(f"{record}")
        else:
            print(f"  {dim('✗')} {dim(rtype):>8}  {dim('No records found')}")

    results['records'] = dns_records

    # Zone transfer attempt
    if args.zone_transfer:
        print_sub_header("Zone Transfer (AXFR)")
        zt_records = _zone_transfer(domain, args.server)

        if zt_records:
            results['zone_transfer'] = zt_records
            print_success(f"Got {len(zt_records)} records from zone transfer:")
            for record in zt_records[:50]:
                print(f"    {dim('│')} {record}")
            if len(zt_records) > 50:
                print(f"    {dim('│')} ... and {len(zt_records) - 50} more records")
        else:
            print_warning("Zone transfer failed or not allowed (this is expected for most domains)")
            results['zone_transfer'] = []

    # Subdomain enumeration
    if args.subdomains:
        print_sub_header("Subdomain Enumeration")
        wordlist = args.wordlist
        print_info(f"Wordlist: {'custom (' + wordlist + ')' if wordlist else 'built-in (' + str(len(DEFAULT_SUBDOMAINS)) + ' entries)'}")
        print()

        found_subs = _enumerate_subdomains(domain, wordlist)

        if found_subs:
            found_subs.sort(key=lambda x: x['subdomain'])
            print()
            print_success(f"Found {len(found_subs)} subdomains:")
            print()
            for sub in found_subs:
                ips_str = ', '.join(sub['ips'])
                print(f"    {success('●')} {bold(sub['subdomain']):<40} {dim('→')} {ips_str}")
        else:
            print_warning("No subdomains found.")

        results['subdomains'] = found_subs

    # Summary
    print()
    print(f"  {dim('─' * 50)}")
    total_records = sum(len(v) for v in dns_records.values())
    print_result("Total records found", str(total_records))
    if args.subdomains:
        print_result("Subdomains found", str(len(results.get('subdomains', []))))

    return {'dns_enum': results}
