"""
Cyber_NetCAT — Main entry point and command dispatcher.
Supports both interactive menu mode and CLI subcommand mode.
"""

import sys
import json
import shlex
from argparse import Namespace
from datetime import datetime

from netcat_tool.cli_parser import build_parser
from netcat_tool.utils.banner import print_banner
from netcat_tool.utils.logger import setup_logger
from netcat_tool.utils.colors import (
    print_error, print_info, print_warning, print_success,
    print_header, print_sub_header, success, error, warning,
    info, dim, bold, Colors
)


# ─── Menu Definition ──────────────────────────────────────────────────
MENU_OPTIONS = [
    {
        'key': '1',
        'name': 'Port Scanner',
        'command': 'scan',
        'icon': '🔍',
        'desc': 'TCP/UDP port scanning with service detection',
        'prompts': [
            {'arg': '-t', 'prompt': 'Target IP/hostname/CIDR', 'required': True},
            {'arg': '-p', 'prompt': 'Ports (e.g. 1-1000, 80,443, common, all)', 'required': False, 'default': 'common'},
            {'arg': '--threads', 'prompt': 'Threads (default: 100)', 'required': False, 'default': ''},
            {'arg': '--udp', 'prompt': 'UDP scan? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--syn', 'prompt': 'SYN stealth scan? (y/N) [requires admin]', 'required': False, 'type': 'bool', 'default': 'n'},
        ],
    },
    {
        'key': '2',
        'name': 'Banner Grabber',
        'command': 'banner',
        'icon': '🏷️',
        'desc': 'Grab service banners from open ports',
        'prompts': [
            {'arg': '-t', 'prompt': 'Target IP/hostname', 'required': True},
            {'arg': '-p', 'prompt': 'Ports (e.g. 21,22,80,443)', 'required': True},
            {'arg': '--probe', 'prompt': 'Send protocol-specific probes? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
        ],
    },
    {
        'key': '3',
        'name': 'DNS Enumeration',
        'command': 'dns',
        'icon': '🌐',
        'desc': 'DNS record lookups, subdomain brute force, zone transfer',
        'prompts': [
            {'arg': '-d', 'prompt': 'Target domain (e.g. example.com)', 'required': True},
            {'arg': '--type', 'prompt': 'Record types (A,AAAA,MX,NS,TXT,CNAME,SOA)', 'required': False, 'default': 'A'},
            {'arg': '--subdomains', 'prompt': 'Enumerate subdomains? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--zone-transfer', 'prompt': 'Attempt zone transfer? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--reverse', 'prompt': 'Reverse DNS lookup IP (leave blank to skip)', 'required': False, 'default': ''},
            {'arg': '--wordlist', 'prompt': 'Custom subdomain wordlist path (leave blank for built-in)', 'required': False, 'default': ''},
        ],
    },
    {
        'key': '4',
        'name': 'Network Recon',
        'command': 'recon',
        'icon': '📡',
        'desc': 'Host discovery, ping sweep, traceroute, OS fingerprinting',
        'prompts': [
            {'arg': '--sweep', 'prompt': 'Ping sweep CIDR (e.g. 192.168.1.0/24, leave blank to skip)', 'required': False, 'default': ''},
            {'arg': '--traceroute', 'prompt': 'Traceroute target (leave blank to skip)', 'required': False, 'default': ''},
            {'arg': '--os-detect', 'prompt': 'OS detection target (leave blank to skip)', 'required': False, 'default': ''},
            {'arg': '--interfaces', 'prompt': 'List network interfaces? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--arp', 'prompt': 'ARP scan CIDR (leave blank to skip)', 'required': False, 'default': ''},
        ],
    },
    {
        'key': '5',
        'name': 'Vulnerability Scanner',
        'command': 'vulnscan',
        'icon': '🛡️',
        'desc': 'CVE mapping, SSL/TLS analysis, HTTP security headers',
        'prompts': [
            {'arg': '-t', 'prompt': 'Target IP/hostname', 'required': True},
            {'arg': '-p', 'prompt': 'Ports (default: common)', 'required': False, 'default': 'common'},
            {'arg': '--full', 'prompt': 'Run ALL checks (CVE + SSL + Headers)? (Y/n)', 'required': False, 'type': 'bool', 'default': 'y'},
            {'arg': '--ssl-check', 'prompt': 'SSL/TLS check only? (y/N) [ignored if --full]', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--headers', 'prompt': 'HTTP headers check only? (y/N) [ignored if --full]', 'required': False, 'type': 'bool', 'default': 'n'},
        ],
    },
    {
        'key': '6',
        'name': 'Packet Crafter',
        'command': 'craft',
        'icon': '📦',
        'desc': 'Custom TCP/UDP/ICMP packet construction and sending',
        'prompts': [
            {'arg': '-t', 'prompt': 'Target IP address', 'required': True},
            {'arg': '-p', 'prompt': 'Target port (default: 80)', 'required': False, 'default': '80'},
            {'arg': 'protocol', 'prompt': 'Protocol (tcp/udp/icmp)', 'required': True, 'type': 'choice', 'choices': ['tcp', 'udp', 'icmp']},
            {'arg': '--flags', 'prompt': 'TCP flags (SYN,ACK,FIN,RST,PSH,URG)', 'required': False, 'default': 'SYN'},
            {'arg': '--data', 'prompt': 'Payload data (leave blank for none)', 'required': False, 'default': ''},
            {'arg': '--count', 'prompt': 'Number of packets (default: 1)', 'required': False, 'default': '1'},
            {'arg': '--spoof', 'prompt': 'Spoof source IP (leave blank for none)', 'required': False, 'default': ''},
            {'arg': '--flood', 'prompt': 'Flood mode? (y/N) [use with caution!]', 'required': False, 'type': 'bool', 'default': 'n'},
        ],
    },
    {
        'key': '7',
        'name': 'Reverse/Bind Shell',
        'command': 'shell',
        'icon': '💻',
        'desc': 'Reverse shell listener/client, bind shell with encryption',
        'prompts': [
            {'arg': 'mode', 'prompt': 'Mode (listen/connect/bind)', 'required': True, 'type': 'choice', 'choices': ['listen', 'connect', 'bind']},
            {'arg': '-p', 'prompt': 'Port number', 'required': True},
            {'arg': '--connect-ip', 'prompt': 'Connect-back IP (only for connect mode)', 'required': False, 'default': '', 'condition': 'connect'},
            {'arg': '--encrypt', 'prompt': 'Enable XOR encryption? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--key', 'prompt': 'Encryption key (default: NetCAT)', 'required': False, 'default': ''},
        ],
    },
    {
        'key': '8',
        'name': 'File Transfer',
        'command': 'transfer',
        'icon': '📁',
        'desc': 'TCP file send/receive with integrity verification',
        'prompts': [
            {'arg': 'mode', 'prompt': 'Mode (send/receive)', 'required': True, 'type': 'choice', 'choices': ['send', 'receive']},
            {'arg': '-p', 'prompt': 'Port number', 'required': True},
            {'arg': '--send-file', 'prompt': 'File path to send (only for send mode)', 'required': False, 'default': ''},
            {'arg': '-t', 'prompt': 'Target IP (only for send mode)', 'required': False, 'default': ''},
            {'arg': '--output-dir', 'prompt': 'Output directory for received files (default: .)', 'required': False, 'default': '.'},
            {'arg': '--compress', 'prompt': 'Compress before transfer? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
        ],
    },
    {
        'key': '9',
        'name': 'Brute Force',
        'command': 'brute',
        'icon': '🔓',
        'desc': 'SSH/FTP/HTTP authentication brute force testing',
        'prompts': [
            {'arg': 'protocol', 'prompt': 'Protocol (ssh/ftp/http)', 'required': True, 'type': 'choice', 'choices': ['ssh', 'ftp', 'http']},
            {'arg': '-t', 'prompt': 'Target IP/hostname', 'required': True},
            {'arg': '-u', 'prompt': 'Username (or username file path)', 'required': True},
            {'arg': '-w', 'prompt': 'Wordlist file path', 'required': True, 'default': 'wordlists/common_passwords.txt'},
            {'arg': '-p', 'prompt': 'Port (leave blank for default)', 'required': False, 'default': ''},
            {'arg': '--delay', 'prompt': 'Delay between attempts in seconds (default: 0.5)', 'required': False, 'default': ''},
            {'arg': '--threads', 'prompt': 'Threads (default: 4)', 'required': False, 'default': ''},
            {'arg': '--url', 'prompt': 'URL path for HTTP brute force (default: /)', 'required': False, 'default': '/'},
        ],
    },
    {
        'key': '10',
        'name': 'Traffic Analyzer',
        'command': 'sniff',
        'icon': '📶',
        'desc': 'Live packet capture and protocol analysis',
        'prompts': [
            {'arg': '--count', 'prompt': 'Number of packets to capture (default: 50)', 'required': False, 'default': '50'},
            {'arg': '--filter', 'prompt': 'Protocol filter (tcp/udp/icmp/http/dns, leave blank for all)', 'required': False, 'default': ''},
            {'arg': '--hex', 'prompt': 'Show hex dump? (y/N)', 'required': False, 'type': 'bool', 'default': 'n'},
            {'arg': '--save', 'prompt': 'Save capture to file (leave blank to skip)', 'required': False, 'default': ''},
            {'arg': '--interface', 'prompt': 'Network interface (leave blank for default)', 'required': False, 'default': ''},
        ],
    },
]


def save_results(results, output_path):
    """
    Save scan results to a JSON file.

    Args:
        results: Dictionary of results to save.
        output_path: File path for the JSON output.
    """
    results['metadata'] = {
        'tool': 'Cyber_NetCAT',
        'timestamp': datetime.now().isoformat(),
    }
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print_info(f"Results saved to: {output_path}")
    except IOError as e:
        print_error(f"Failed to save results: {e}")


def dispatch(args):
    """
    Dispatch the parsed CLI arguments to the appropriate module.

    Args:
        args: Parsed argparse.Namespace object.

    Returns:
        Results dictionary from the executed module, or None.
    """
    command = args.command
    results = None

    if command == 'scan':
        from netcat_tool.modules.port_scanner import run_scan
        results = run_scan(args)

    elif command == 'banner':
        from netcat_tool.modules.banner_grabber import run_banner_grab
        results = run_banner_grab(args)

    elif command == 'dns':
        from netcat_tool.modules.dns_enum import run_dns_enum
        results = run_dns_enum(args)

    elif command == 'recon':
        from netcat_tool.modules.network_recon import run_recon
        results = run_recon(args)

    elif command == 'vulnscan':
        from netcat_tool.modules.vuln_scanner import run_vuln_scan
        results = run_vuln_scan(args)

    elif command == 'craft':
        from netcat_tool.modules.packet_crafter import run_craft
        results = run_craft(args)

    elif command == 'shell':
        from netcat_tool.modules.reverse_shell import run_shell
        results = run_shell(args)

    elif command == 'transfer':
        from netcat_tool.modules.file_transfer import run_transfer
        results = run_transfer(args)

    elif command == 'brute':
        from netcat_tool.modules.brute_force import run_brute
        results = run_brute(args)

    elif command == 'sniff':
        from netcat_tool.modules.traffic_analyzer import run_sniff
        results = run_sniff(args)

    else:
        print_error(f"Unknown command: {command}")
        return None

    return results


def _fix_encoding():
    """Fix Windows console encoding for Unicode characters."""
    import io
    if sys.stdout.encoding != 'utf-8':
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except AttributeError:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    if sys.stderr.encoding != 'utf-8':
        try:
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
        except AttributeError:
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


def _print_menu():
    """Print the interactive main menu."""
    print(f"\n  {bold('╔══════════════════════════════════════════════════════════════╗')}")
    print(f"  {bold('║')}  {info('SELECT A MODULE')}                                              {bold('║')}")
    print(f"  {bold('╠══════════════════════════════════════════════════════════════╣')}")

    for opt in MENU_OPTIONS:
        num = opt['key'].rjust(2)
        name = opt['name']
        desc = opt['desc']
        icon = opt['icon']
        print(f"  {bold('║')}                                                              {bold('║')}")
        print(f"  {bold('║')}   {success(f'[{num}]')}  {icon}  {bold(f'{name:<22}')} {dim(f'{desc[:33]}')}  {bold('║')}")

    print(f"  {bold('║')}                                                              {bold('║')}")
    print(f"  {bold('╠══════════════════════════════════════════════════════════════╣')}")
    print(f"  {bold('║')}                                                              {bold('║')}")
    print(f"  {bold('║')}   {error('[0]')}  🚪  {bold('Exit')}                                              {bold('║')}")
    print(f"  {bold('║')}                                                              {bold('║')}")
    print(f"  {bold('╚══════════════════════════════════════════════════════════════╝')}")


def _prompt_input(prompt_text, required=False, default=''):
    """
    Prompt the user for input with optional default.

    Args:
        prompt_text: The prompt message.
        required: Whether input is required.
        default: Default value if user presses Enter.

    Returns:
        User input string.
    """
    default_hint = f" {dim(f'[{default}]')}" if default else ""
    required_hint = f" {error('*')}" if required else ""

    while True:
        try:
            value = input(f"    {info('>')} {prompt_text}{required_hint}{default_hint}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        if not value and default:
            return default
        if not value and required:
            print_error("    This field is required. Please enter a value.")
            continue
        if not value:
            return ''
        return value


def _build_args_from_prompts(option):
    """
    Interactively prompt the user for all arguments of a module
    and build an argparse-compatible Namespace.

    Args:
        option: Menu option dictionary with prompts.

    Returns:
        argparse.Namespace with all arguments, or None if cancelled.
    """
    command = option['command']

    print(f"\n  {bold('─' * 50)}")
    print(f"  {info('Configure:')} {bold(option['name'])}")
    print(f"  {dim(option['desc'])}")
    print(f"  {dim('Press Ctrl+C to cancel and return to menu')}")
    print(f"  {bold('─' * 50)}\n")

    # Build CLI argument list from interactive prompts
    cli_args = [command]

    for p in option['prompts']:
        arg_name = p['arg']
        prompt_text = p['prompt']
        required = p.get('required', False)
        default = p.get('default', '')
        arg_type = p.get('type', 'str')

        if arg_type == 'bool':
            value = _prompt_input(prompt_text, required=False, default=default)
            if value is None:
                return None
            if value.lower() in ('y', 'yes', '1', 'true'):
                # Only add flag if it's an actual argparse flag
                if arg_name.startswith('-'):
                    cli_args.append(arg_name)
        elif arg_type == 'choice':
            choices = p.get('choices', [])
            prompt_with_choices = f"{prompt_text} ({'/'.join(choices)})"
            value = _prompt_input(prompt_with_choices, required=required, default=default)
            if value is None:
                return None
            if value and value.lower() not in choices:
                print_warning(f"Invalid choice. Options: {', '.join(choices)}")
                return None
            # Handle special protocol/mode mappings
            if arg_name == 'protocol':
                if command == 'craft':
                    cli_args.append(f'--{value.lower()}')
                elif command == 'brute':
                    cli_args.append(f'--{value.lower()}')
            elif arg_name == 'mode':
                if command == 'shell':
                    if value == 'listen':
                        cli_args.append('--listen')
                    elif value == 'connect':
                        # Need the connect IP
                        connect_ip = _prompt_input('Connect-back IP address', required=True)
                        if connect_ip is None:
                            return None
                        cli_args.extend(['--connect', connect_ip])
                    elif value == 'bind':
                        cli_args.append('--bind')
                elif command == 'transfer':
                    if value == 'send':
                        filepath = _prompt_input('File path to send', required=True)
                        if filepath is None:
                            return None
                        cli_args.extend(['--send', filepath])
                    elif value == 'receive':
                        cli_args.append('--receive')
        else:
            # Standard string argument
            # Skip special handled args
            if arg_name in ('--connect-ip', '--send-file'):
                continue

            value = _prompt_input(prompt_text, required=required, default=default)
            if value is None:
                return None

            if value:
                if arg_name.startswith('-'):
                    cli_args.extend([arg_name, value])
                # else: positional — handled by special cases above

    # Parse the constructed CLI args through argparse
    parser = build_parser()
    try:
        args = parser.parse_args(cli_args)
        return args
    except SystemExit:
        print_error("Invalid arguments. Please try again.")
        return None


def _interactive_menu():
    """
    Run the interactive menu loop.
    Shows module options, prompts for parameters, runs the module,
    then returns to the menu.
    """
    setup_logger(verbose=False)

    while True:
        _print_menu()

        try:
            choice = input(f"\n  {bold('Enter your choice')} {dim('[0-10]')}: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print_info("Goodbye!")
            break

        # Exit
        if choice == '0':
            print()
            print(f"  {dim('─' * 50)}")
            print_success("Thank you for using Cyber_NetCAT. Stay safe!")
            print(f"  {dim('─' * 50)}")
            break

        # Find selected option
        selected = None
        for opt in MENU_OPTIONS:
            if opt['key'] == choice:
                selected = opt
                break

        if not selected:
            print_error(f"Invalid choice: '{choice}'. Please enter 0-10.")
            continue

        # Build args from interactive prompts
        args = _build_args_from_prompts(selected)
        if args is None:
            print_warning("Operation cancelled. Returning to main menu...")
            continue

        # Add global defaults
        args.no_banner = True  # Banner already shown
        args.verbose = False
        args.output = None
        if not hasattr(args, 'timeout'):
            args.timeout = 2.0

        # Ask if they want to save results
        save_path = _prompt_input("Save results to JSON file? (leave blank to skip)", required=False, default='')

        # Run the module
        print(f"\n{'=' * 60}")
        try:
            results = dispatch(args)

            if results and save_path:
                save_results(results, save_path)

        except KeyboardInterrupt:
            print()
            print_warning("Operation interrupted (Ctrl+C). Returning to menu...")
        except PermissionError:
            print_error("Insufficient permissions. Try running as administrator.")
        except Exception as e:
            print_error(f"Error: {e}")

        # Pause before returning to menu
        print(f"\n{'=' * 60}")
        try:
            input(f"\n  {dim('Press Enter to return to main menu...')}")
        except (EOFError, KeyboardInterrupt):
            pass


def main():
    """Main entry point for Cyber_NetCAT."""
    _fix_encoding()

    # Check if CLI arguments were provided (subcommand mode)
    # If args beyond the script name exist, use CLI mode
    if len(sys.argv) > 1:
        # CLI subcommand mode (backward compatible)
        parser = build_parser()
        args = parser.parse_args()

        if not args.no_banner:
            print_banner()

        if not args.command:
            parser.print_help()
            print()
            print_warning("No command specified. Use one of the commands above.")
            sys.exit(0)

        log_file = None
        if args.verbose:
            log_file = f"logs/netcat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        logger = setup_logger(verbose=args.verbose, log_file=log_file)

        if args.verbose:
            logger.debug(f"Command: {args.command}")
            logger.debug(f"Arguments: {vars(args)}")

        try:
            results = dispatch(args)
            if results and args.output:
                save_results(results, args.output)
        except KeyboardInterrupt:
            print()
            print_warning("Operation interrupted by user (Ctrl+C)")
            sys.exit(130)
        except PermissionError:
            print_error("Insufficient permissions. Try running as administrator/root.")
            sys.exit(1)
        except Exception as e:
            print_error(f"Unexpected error: {e}")
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(1)
    else:
        # Interactive menu mode — no arguments provided
        print_banner()
        _interactive_menu()


if __name__ == '__main__':
    main()
