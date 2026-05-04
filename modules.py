"""
Scan modules - each module defines an Nmap scan type
"""

from dataclasses import dataclass, field
from typing import Optional

@dataclass
class ScanModule:
    name: str
    description: str
    category: str
    nmap_args: str
    output_formats: list[str] = field(default_factory=lambda: ["-oA"])
    requires_root: bool = False
    example: str = ""

# ──────────────────────────────────────────────
# MODULE REGISTRY
# ──────────────────────────────────────────────
MODULES: dict[str, ScanModule] = {

    # ── DISCOVERY ──────────────────────────────
    "discovery/ping_sweep": ScanModule(
        name="discovery/ping_sweep",
        category="discovery",
        description="Fast host discovery — no port scan, just checks which hosts are alive",
        nmap_args="-sn",
        requires_root=False,
        example="nmap -sn 192.168.1.0/24",
    ),
    "discovery/arp_sweep": ScanModule(
        name="discovery/arp_sweep",
        category="discovery",
        description="ARP-based host discovery (LAN only, very reliable)",
        nmap_args="-PR -sn",
        requires_root=True,
        example="nmap -PR -sn 192.168.1.0/24",
    ),
    "discovery/traceroute": ScanModule(
        name="discovery/traceroute",
        category="discovery",
        description="Trace network path to each host",
        nmap_args="-sn --traceroute",
        requires_root=False,
        example="nmap -sn --traceroute 192.168.1.1",
    ),

    # ── PORT SCANS ─────────────────────────────
    "portscan/quick": ScanModule(
        name="portscan/quick",
        category="portscan",
        description="Fast scan of top 100 most common ports",
        nmap_args="-F",
        requires_root=False,
        example="nmap -F 192.168.1.1",
    ),
    "portscan/top1000": ScanModule(
        name="portscan/top1000",
        category="portscan",
        description="Default scan — top 1000 ports (TCP SYN if root, else connect)",
        nmap_args="",
        requires_root=False,
        example="nmap 192.168.1.1",
    ),
    "portscan/full_tcp": ScanModule(
        name="portscan/full_tcp",
        category="portscan",
        description="Full TCP scan of all 65535 ports",
        nmap_args="-p- --open",
        requires_root=False,
        example="nmap -p- --open 192.168.1.1",
    ),
    "portscan/syn_stealth": ScanModule(
        name="portscan/syn_stealth",
        category="portscan",
        description="TCP SYN stealth scan (half-open, faster, requires root)",
        nmap_args="-sS",
        requires_root=True,
        example="nmap -sS 192.168.1.1",
    ),
    "portscan/udp": ScanModule(
        name="portscan/udp",
        category="portscan",
        description="UDP port scan (slower, requires root)",
        nmap_args="-sU --top-ports 200",
        requires_root=True,
        example="nmap -sU --top-ports 200 192.168.1.1",
    ),
    "portscan/tcp_udp": ScanModule(
        name="portscan/tcp_udp",
        category="portscan",
        description="Combined TCP + UDP scan",
        nmap_args="-sSU --top-ports 100",
        requires_root=True,
        example="nmap -sSU --top-ports 100 192.168.1.1",
    ),
    "portscan/connect": ScanModule(
        name="portscan/connect",
        category="portscan",
        description="TCP connect scan (no root needed, more detectable)",
        nmap_args="-sT",
        requires_root=False,
        example="nmap -sT 192.168.1.1",
    ),

    # ── ENUMERATION ────────────────────────────
    "enum/service_version": ScanModule(
        name="enum/service_version",
        category="enum",
        description="Detect service versions on open ports",
        nmap_args="-sV",
        requires_root=False,
        example="nmap -sV 192.168.1.1",
    ),
    "enum/os_detect": ScanModule(
        name="enum/os_detect",
        category="enum",
        description="Attempt OS fingerprinting (requires root)",
        nmap_args="-O",
        requires_root=True,
        example="nmap -O 192.168.1.1",
    ),
    "enum/aggressive": ScanModule(
        name="enum/aggressive",
        category="enum",
        description="Aggressive scan: OS, version, scripts, traceroute (-A)",
        nmap_args="-A",
        requires_root=False,
        example="nmap -A 192.168.1.1",
    ),
    "enum/banner_grab": ScanModule(
        name="enum/banner_grab",
        category="enum",
        description="Grab service banners using NSE banner script",
        nmap_args="-sV --script=banner",
        requires_root=False,
        example="nmap -sV --script=banner 192.168.1.1",
    ),

    # ── SCRIPTS / NSE ──────────────────────────
    "scripts/default": ScanModule(
        name="scripts/default",
        category="scripts",
        description="Run default NSE scripts (-sC)",
        nmap_args="-sC",
        requires_root=False,
        example="nmap -sC 192.168.1.1",
    ),
    "scripts/vuln": ScanModule(
        name="scripts/vuln",
        category="scripts",
        description="Run vulnerability detection NSE scripts",
        nmap_args="--script=vuln",
        requires_root=False,
        example="nmap --script=vuln 192.168.1.1",
    ),
    "scripts/http": ScanModule(
        name="scripts/http",
        category="scripts",
        description="HTTP enumeration scripts (titles, methods, headers, dirs)",
        nmap_args="-p 80,443,8080,8443 --script=http-title,http-methods,http-headers,http-enum",
        requires_root=False,
        example="nmap -p80,443 --script=http-title,http-methods 192.168.1.1",
    ),
    "scripts/smb": ScanModule(
        name="scripts/smb",
        category="scripts",
        description="SMB enumeration (shares, users, OS, security)",
        nmap_args="-p 139,445 --script=smb-enum-shares,smb-enum-users,smb-os-discovery,smb-security-mode",
        requires_root=False,
        example="nmap -p445 --script=smb-enum-shares 192.168.1.1",
    ),
    "scripts/ftp": ScanModule(
        name="scripts/ftp",
        category="scripts",
        description="FTP enumeration (anon login, banner, bounce)",
        nmap_args="-p 21 --script=ftp-anon,ftp-banner,ftp-bounce",
        requires_root=False,
        example="nmap -p21 --script=ftp-anon 192.168.1.1",
    ),
    "scripts/ssh": ScanModule(
        name="scripts/ssh",
        category="scripts",
        description="SSH enumeration (host-key, auth methods, algorithms)",
        nmap_args="-p 22 --script=ssh-hostkey,ssh-auth-methods,ssh2-enum-algos",
        requires_root=False,
        example="nmap -p22 --script=ssh-hostkey 192.168.1.1",
    ),
    "scripts/dns": ScanModule(
        name="scripts/dns",
        category="scripts",
        description="DNS enumeration (zone transfer, brute, service info)",
        nmap_args="-p 53 --script=dns-zone-transfer,dns-brute,dns-service-discovery",
        requires_root=False,
        example="nmap -p53 --script=dns-zone-transfer 192.168.1.1",
    ),
    "scripts/snmp": ScanModule(
        name="scripts/snmp",
        category="scripts",
        description="SNMP enumeration (community strings, info, interfaces)",
        nmap_args="-sU -p 161 --script=snmp-info,snmp-interfaces,snmp-brute",
        requires_root=True,
        example="nmap -sU -p161 --script=snmp-info 192.168.1.1",
    ),
    "scripts/ssl": ScanModule(
        name="scripts/ssl",
        category="scripts",
        description="SSL/TLS analysis (cert, ciphers, heartbleed, poodle)",
        nmap_args="-p 443,8443 --script=ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle",
        requires_root=False,
        example="nmap -p443 --script=ssl-cert,ssl-enum-ciphers 192.168.1.1",
    ),

    # ── TIMING PROFILES ────────────────────────
    "timing/sneaky": ScanModule(
        name="timing/sneaky",
        category="timing",
        description="Slow, low-noise scan (T1 timing — very slow)",
        nmap_args="-T1",
        requires_root=False,
        example="nmap -T1 192.168.1.1",
    ),
    "timing/polite": ScanModule(
        name="timing/polite",
        category="timing",
        description="Polite scan (T2 — slow, reduces bandwidth)",
        nmap_args="-T2",
        requires_root=False,
        example="nmap -T2 192.168.1.1",
    ),
    "timing/aggressive": ScanModule(
        name="timing/aggressive",
        category="timing",
        description="Aggressive timing (T4 — fast, good for local nets)",
        nmap_args="-T4",
        requires_root=False,
        example="nmap -T4 192.168.1.1",
    ),
    "timing/insane": ScanModule(
        name="timing/insane",
        category="timing",
        description="Insane timing (T5 — fastest, may miss results)",
        nmap_args="-T5",
        requires_root=False,
        example="nmap -T5 192.168.1.1",
    ),
}


def search_modules(keyword: str) -> list[ScanModule]:
    """Return modules whose name, description, or category contain the keyword."""
    kw = keyword.lower()
    return [
        m for m in MODULES.values()
        if kw in m.name.lower()
        or kw in m.description.lower()
        or kw in m.category.lower()
    ]


def get_module(name: str) -> Optional[ScanModule]:
    return MODULES.get(name)


def list_categories() -> list[str]:
    return sorted(set(m.category for m in MODULES.values()))
