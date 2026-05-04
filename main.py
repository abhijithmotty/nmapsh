#!/usr/bin/env python3
"""
NmapShell - Interactive Nmap Automation Framework
A Metasploit-style shell for running Nmap scans
"""

from shell import NmapShell

if __name__ == "__main__":
    shell = NmapShell()
    shell.run()
