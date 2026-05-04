# NmapShell

```
  ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ███████╗██╗  ██╗
  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗██╔════╝██║  ██║
  ██╔██╗ ██║██╔████╔██║███████║██████╔╝███████╗███████║
  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ╚════██║██╔══██║
  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ███████║██║  ██║
  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝

  Interactive Nmap Automation Framework
  A Metasploit-style shell for running Nmap scans
```

---

## Overview

NmapShell is a lightweight, interactive command-line framework for automating
Nmap scans. It follows a Metasploit-style workflow — search for a module,
load it, set your target, and run. No flags to memorize, no long commands
to type out every time.

It supports single-module scans as well as multi-module scans, where you
queue up several scan types and run them all against the same target in one go.

---

## Requirements

- Python 3.11 or higher
- Nmap installed and available in PATH

Install Nmap on Debian / Kali / Ubuntu:

```
sudo apt update && sudo apt install nmap -y
```

No third-party Python packages required. NmapShell uses only the standard library.

---

## Installation

```
https://github.com/abhijithmotty/NMAPSH.git
cd NMAPSH
python3 main.py
```

---

## Project Structure

```
nmapshell/
├── main.py          Entry point
├── shell.py         Interactive console and all commands
├── modules.py       Scan module definitions (27 modules)
├── runner.py        Builds and executes nmap commands
└── requirements.txt Dependencies (none required)
```

---

## Usage

Launch the shell:

```
python3 main.py
```

Basic workflow:

```
nmapsh > search http
nmapsh > use scripts/http
nmapsh(scripts/http) > set target 192.168.1.1
nmapsh(scripts/http) > set timing -T4
nmapsh(scripts/http) > run
```

Multi-module scan (run several modules against the same target):

```
nmapsh > use multi
nmapsh(multi:0) > add portscan/quick
nmapsh(multi:1) > add scripts/http
nmapsh(multi:2) > add scripts/ssh
nmapsh(multi:3) > add scripts/ftp
nmapsh(multi:4) > set target 192.168.1.1
nmapsh(multi:4) > run
```

---

## Modules

27 built-in modules across 5 categories.

### discovery
```
discovery/arp_sweep       ARP-based host discovery (LAN only)
discovery/ping_sweep      Fast host discovery, no port scan
discovery/traceroute      Trace network path to each host
```

### portscan
```
portscan/connect          TCP connect scan, no root needed
portscan/full_tcp         Full scan of all 65535 TCP ports
portscan/quick            Fast scan of top 100 common ports
portscan/syn_stealth      TCP SYN stealth scan, requires root
portscan/tcp_udp          Combined TCP and UDP scan
portscan/top1000          Default scan of top 1000 ports
portscan/udp              UDP port scan, requires root
```

### enum
```
enum/aggressive           Full -A scan: OS, version, scripts, traceroute
enum/banner_grab          Grab service banners via NSE
enum/os_detect            OS fingerprinting, requires root
enum/service_version      Detect service and software versions
```

### scripts
```
scripts/default           Run default NSE scripts
scripts/dns               DNS zone transfer, brute, service discovery
scripts/ftp               FTP anon login, banner, bounce check
scripts/http              HTTP titles, methods, headers, enumeration
scripts/smb               SMB shares, users, OS, security mode
scripts/snmp              SNMP community string enumeration
scripts/ssh               SSH host key, auth methods, algorithms
scripts/ssl               SSL cert, ciphers, heartbleed, poodle
scripts/vuln              Vulnerability detection scripts
```

### timing
```
timing/aggressive         T4 - fast, good for local networks
timing/insane             T5 - maximum speed
timing/polite             T2 - slow, reduces bandwidth usage
timing/sneaky             T1 - very slow, low noise
```

---

## Options

| Option  | Required | Description                              |
|---------|----------|------------------------------------------|
| target  | yes      | IP, hostname, CIDR, or range             |
| ports   | no       | Override ports  e.g. 80,443 or 1-1024    |
| timing  | no       | Timing flag  e.g. -T4                    |
| extra   | no       | Any additional raw nmap flags            |
| outfile | no       | Base name for output files               |

---

## Output Files

Every scan automatically saves three files into `nmap_results/`:

```
.nmap     Human-readable output
.xml      Machine-parseable XML
.gnmap    Grepable format
```

Files are named by module, target, and timestamp:

```
nmap_results/portscan_quick_192.168.1.1_20240501_143022.nmap
nmap_results/portscan_quick_192.168.1.1_20240501_143022.xml
nmap_results/portscan_quick_192.168.1.1_20240501_143022.gnmap
```

View saved files from within the shell:

```
nmapsh > results
```

---

## Help System

```
help                  Main command reference
help search           Keyword guide for finding modules
help set              All options explained with examples
help multi            Multi-module mode guide
help workflow         Step-by-step example workflows
help targets          Target format examples
help timing           Timing flag reference
help output           Output file format guide
```

---

## Common Workflows

Web server recon:
```
use multi
add portscan/quick
add scripts/http
add scripts/ssl
set target 192.168.1.50
run
```

Windows / SMB host:
```
use multi
add portscan/top1000
add scripts/smb
add scripts/dns
set target 192.168.1.10
run
```

Full service fingerprint:
```
use multi
add portscan/full_tcp
add enum/service_version
add enum/os_detect
set target 192.168.1.1
set timing -T4
run
```

---

## Disclaimer

This tool is intended for use on systems you own or have explicit written
permission to test. Unauthorized scanning of networks or systems is illegal
in most jurisdictions. The author assumes no responsibility for misuse.
Always obtain proper authorization before running any scans.

---

## License

MIT License. See LICENSE for details.
