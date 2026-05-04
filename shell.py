"""
shell.py — NmapShell interactive console (Metasploit-style)
Supports single-module and multi-module scans
"""

import os
import sys
import readline
from typing import Optional

from modules import MODULES, ScanModule, search_modules, get_module, list_categories
from runner import ScanConfig, run_scan, OUTPUT_DIR

# ── ANSI colours ────────────────────────────────────────────────
R  = "\033[31m"
G  = "\033[32m"
Y  = "\033[33m"
B  = "\033[34m"
M  = "\033[35m"
C  = "\033[36m"
W  = "\033[37m"
BLD= "\033[1m"
DIM= "\033[2m"
RST= "\033[0m"


BANNER = f"""{R}{BLD}
  ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ███████╗██╗  ██╗
  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗██╔════╝██║  ██║
  ██╔██╗ ██║██╔████╔██║███████║██████╔╝███████╗███████║
  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ╚════██║██╔══██║
  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ███████║██║  ██║
  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{RST}{Y}  Interactive Nmap Automation Framework{RST}
  {DIM}Version 1.1  |  For authorized use only{RST}

  Type {C}help{RST} to get started  |  {C}use multi{RST} to run multiple modules at once
"""

# ═══════════════════════════════════════════════════════════════
#  HELP STRINGS
# ═══════════════════════════════════════════════════════════════

HELP_MAIN = f"""
{BLD}{C}╔══════════════════════════════════════════════════════╗
║              NmapShell  —  Command Reference         ║
╚══════════════════════════════════════════════════════╝{RST}

{BLD}{C}HELP TOPICS{RST}  (type: help <topic>)
  {G}help search{RST}      Keyword list for finding modules
  {G}help set{RST}         All options explained with examples
  {G}help modules{RST}     Full module list
  {G}help multi{RST}       How to run multiple modules in one scan
  {G}help workflow{RST}    Step-by-step example workflows
  {G}help targets{RST}     IP / CIDR / range format guide
  {G}help timing{RST}      Timing flags -T0 to -T5 explained
  {G}help output{RST}      Output file formats (.nmap .xml .gnmap)

{BLD}{C}CORE COMMANDS{RST}
  {G}search  <keyword>{RST}         Search modules by keyword
  {G}use     <module/name>{RST}     Load a single module
  {G}use     multi{RST}             Enter multi-module scan mode
  {G}show    modules{RST}           List every module
  {G}show    categories{RST}        List module categories
  {G}show    options{RST}           Show options for loaded module
  {G}info{RST}                      Full info + nmap args for loaded module
  {G}set     <option> <value>{RST}  Set an option
  {G}unset   <option>{RST}          Clear an option
  {G}run{RST}                       Execute the scan
  {G}results{RST}                   List saved output files
  {G}back{RST}                      Unload current module / leave multi mode
  {G}clear{RST}                     Clear the screen
  {G}exit / quit{RST}               Exit NmapShell

{BLD}{C}MULTI-MODULE COMMANDS{RST}  (only active inside 'use multi')
  {G}add     <module/name>{RST}     Add a module to the scan queue
  {G}remove  <module/name>{RST}     Remove a module from the queue
  {G}list{RST}                      Show queued modules
  {G}clear_queue{RST}               Remove all modules from queue

  {DIM}Tip: press TAB anywhere to auto-complete commands and module names{RST}
"""

HELP_MULTI = f"""
{BLD}{C}MULTI-MODULE SCAN MODE{RST}
  Run several scan types against the same target in one session.
  Each module runs as a separate nmap command, results saved individually.

{BLD}How to use:{RST}
  nmapsh > {C}use multi{RST}
  nmapsh(multi) > {C}add portscan/quick{RST}
  nmapsh(multi) > {C}add scripts/http{RST}
  nmapsh(multi) > {C}add scripts/ssh{RST}
  nmapsh(multi) > {C}add scripts/ftp{RST}
  nmapsh(multi) > {C}list{RST}               <- review the queue
  nmapsh(multi) > {C}set target 192.168.1.1{RST}
  nmapsh(multi) > {C}set timing -T4{RST}
  nmapsh(multi) > {C}run{RST}                <- runs all modules in sequence

{BLD}Managing the queue:{RST}
  {G}add <module>{RST}          Add to queue (duplicates ignored)
  {G}remove <module>{RST}       Remove one module from queue
  {G}list{RST}                  Show what is queued with index numbers
  {G}clear_queue{RST}           Wipe the whole queue
  {G}back{RST}                  Leave multi mode (queue is cleared)

{BLD}Good combinations:{RST}
  {Y}Web server recon:{RST}
    add portscan/quick  +  add scripts/http  +  add scripts/ssl

  {Y}Windows / AD host:{RST}
    add portscan/top1000  +  add scripts/smb  +  add scripts/dns

  {Y}Full service fingerprint:{RST}
    add portscan/full_tcp  +  add enum/service_version  +  add enum/os_detect

  {Y}Common services:{RST}
    add scripts/ftp  +  add scripts/ssh  +  add scripts/http  +  add scripts/smb

{BLD}Notes:{RST}
  Options (target, timing, extra, ports) are shared across all modules.
  Each module saves its own output file in nmap_results/.
  Modules needing root are flagged -- run with sudo if needed.
  Use 'results' after running to see all saved files.
"""

HELP_SEARCH = f"""
{BLD}{C}SEARCH COMMAND{RST}
  Usage: {G}search <keyword>{RST}

{BLD}By service / protocol:{RST}
  {Y}http{RST}       HTTP enumeration (titles, methods, dirs)
  {Y}smb{RST}        SMB/Windows shares, users, security
  {Y}ftp{RST}        FTP anon login, banner, bounce check
  {Y}ssh{RST}        SSH host-key, auth methods, algorithms
  {Y}ssl{RST}        SSL/TLS cert, ciphers, heartbleed
  {Y}dns{RST}        DNS zone transfer, brute, service info
  {Y}snmp{RST}       SNMP community string enum
  {Y}vuln{RST}       Vulnerability detection scripts

{BLD}By scan type:{RST}
  {Y}port{RST}       All port scan modules
  {Y}udp{RST}        UDP scanning
  {Y}syn{RST}        SYN stealth scan (requires root)
  {Y}connect{RST}    TCP connect scan (no root needed)
  {Y}full{RST}       All 65535 ports
  {Y}quick{RST}      Fast top-100 ports

{BLD}By goal:{RST}
  {Y}discovery{RST}  Find live hosts on a network
  {Y}version{RST}    Detect service/software versions
  {Y}os{RST}         Operating system fingerprinting
  {Y}script{RST}     NSE script-based scans
  {Y}aggressive{RST} Full -A scan (OS + version + scripts)
  {Y}banner{RST}     Grab service banners

{BLD}By category name:{RST}
  {Y}portscan  discovery  enum  scripts  timing{RST}
"""

HELP_SET = f"""
{BLD}{C}SET COMMAND -- Options Reference{RST}
  Usage: {G}set <option> <value>{RST}
  Usage: {G}unset <option>{RST}

{BLD}{C}OPTIONS{RST}

  {Y}target{RST}   {R}(required){RST}
    Examples:
      {C}set target 192.168.1.1{RST}
      {C}set target 192.168.1.0/24{RST}
      {C}set target scanme.nmap.org{RST}

  {Y}ports{RST}    {DIM}(optional -- overrides module default){RST}
    Examples:
      {C}set ports 80,443{RST}
      {C}set ports 1-1024{RST}
      {C}set ports -{RST}          <- all 65535 ports

  {Y}timing{RST}   {DIM}(optional){RST}
    Examples:
      {C}set timing -T1{RST}       <- slow / sneaky
      {C}set timing -T4{RST}       <- fast / recommended

  {Y}extra{RST}    {DIM}(optional -- any raw nmap flags){RST}
    Examples:
      {C}set extra --open{RST}
      {C}set extra -v --open{RST}
      {C}set extra --script-args user=admin{RST}

  {Y}outfile{RST}  {DIM}(optional -- base filename, no extension){RST}
    Example:
      {C}set outfile my_scan{RST}
      -> saves: my_scan.nmap / my_scan.xml / my_scan.gnmap
    In multi mode, module name is appended automatically.
"""

HELP_TARGETS = f"""
{BLD}{C}TARGET FORMATS{RST}
  {C}set target 192.168.1.1{RST}              Single IP
  {C}set target 192.168.1.0/24{RST}           CIDR subnet (256 hosts)
  {C}set target 10.0.0.0/16{RST}              Larger subnet
  {C}set target 192.168.1.1-50{RST}           IP range (.1 to .50)
  {C}set target 192.168.1.1 192.168.1.5{RST}  Multiple IPs
  {C}set target scanme.nmap.org{RST}           Hostname
  {C}set target example.com{RST}               Domain
"""

HELP_TIMING = f"""
{BLD}{C}TIMING FLAGS  (-T0 to -T5){RST}
  Use with:  {G}set timing -T<n>{RST}

  {Y}-T0{RST}  Paranoid    One probe every 5 min. Maximum stealth.
  {Y}-T1{RST}  Sneaky      Very slow. Reduces IDS detection chance.
  {Y}-T2{RST}  Polite      Slower than default. Saves bandwidth.
  {Y}-T3{RST}  Normal      Default nmap timing. Balanced.
  {Y}-T4{RST}  Aggressive  Fast. Good for local networks. {G}<- Recommended{RST}
  {Y}-T5{RST}  Insane      Maximum speed. May miss results.
"""

HELP_OUTPUT = f"""
{BLD}{C}OUTPUT FILES  ->  saved in {Y}nmap_results/{RST}

  {G}.nmap{RST}    Human-readable (same as terminal output)
  {G}.xml{RST}     Machine-parseable XML
  {G}.gnmap{RST}   Grepable format

  Files are named:  {C}<module>_<target>_<timestamp>{RST}
  View them:        {G}results{RST}

  Grep open ports (outside NmapShell):
    {DIM}grep "open" nmap_results/*.gnmap{RST}
    {DIM}grep "80/open" nmap_results/*.gnmap{RST}
"""

HELP_WORKFLOW = f"""
{BLD}{C}EXAMPLE WORKFLOWS{RST}

{BLD}1. Quick port scan{RST}
   {C}use portscan/quick{RST}
   {C}set target 192.168.1.1{RST}
   {C}run{RST}

{BLD}2. Full web server recon (multi){RST}
   {C}use multi{RST}
   {C}add portscan/quick{RST}
   {C}add scripts/http{RST}
   {C}add scripts/ssl{RST}
   {C}set target 192.168.1.50{RST}
   {C}set timing -T4{RST}
   {C}run{RST}

{BLD}3. Windows host (multi){RST}
   {C}use multi{RST}
   {C}add portscan/top1000{RST}
   {C}add scripts/smb{RST}
   {C}add scripts/dns{RST}
   {C}set target 192.168.1.10{RST}
   {C}run{RST}

{BLD}4. Common services sweep (multi){RST}
   {C}use multi{RST}
   {C}add scripts/ftp{RST}
   {C}add scripts/ssh{RST}
   {C}add scripts/http{RST}
   {C}add scripts/smb{RST}
   {C}add scripts/ssl{RST}
   {C}set target 10.10.10.5{RST}
   {C}set timing -T4{RST}
   {C}run{RST}

{BLD}5. Full aggressive single scan{RST}
   {C}use enum/aggressive{RST}
   {C}set target 192.168.1.1{RST}
   {C}set extra --open{RST}
   {C}run{RST}
"""

HELP_TOPICS = {
    "search":   HELP_SEARCH,
    "set":      HELP_SET,
    "modules":  None,
    "multi":    HELP_MULTI,
    "workflow": HELP_WORKFLOW,
    "targets":  HELP_TARGETS,
    "timing":   HELP_TIMING,
    "output":   HELP_OUTPUT,
}

# ═══════════════════════════════════════════════════════════════
#  SHELL
# ═══════════════════════════════════════════════════════════════

class NmapShell:
    def __init__(self):
        self.module: Optional[ScanModule] = None
        self.multi_mode: bool = False
        self.queue: list[ScanModule] = []
        self.options: dict = {
            "target":  "",
            "ports":   "",
            "timing":  "",
            "extra":   "",
            "outfile": "",
        }
        self._setup_readline()

    # ── readline / tab completion ────────────────────────────────
    def _setup_readline(self):
        base_commands  = [
            "search ", "use ", "show ", "set ", "unset ", "run",
            "info", "back", "results", "clear", "help", "exit", "quit",
        ]
        multi_commands = ["add ", "remove ", "list", "clear_queue"]
        all_commands   = base_commands + multi_commands

        show_opts    = ["modules", "categories", "options"]
        set_opts     = ["target ", "ports ", "timing ", "extra ", "outfile "]
        help_opts    = list(HELP_TOPICS.keys())
        module_names = list(MODULES.keys())

        def completer(text, state):
            options_list: list[str] = []
            buf   = readline.get_line_buffer().lstrip()
            parts = buf.split()
            first = parts[0].lower() if parts else ""

            if len(parts) == 0 or (len(parts) == 1 and not buf.endswith(" ")):
                cmds = all_commands if self.multi_mode else base_commands
                options_list = [c for c in cmds if c.startswith(text)]
            elif first in ("use", "add", "remove"):
                options_list = [m for m in module_names if m.startswith(text)]
                if first == "use" and "multi".startswith(text):
                    options_list = ["multi"] + options_list
            elif first == "show":
                options_list = [o for o in show_opts if o.startswith(text)]
            elif first in ("help", "?"):
                options_list = [o for o in help_opts if o.startswith(text)]
            elif first == "set":
                options_list = [o for o in set_opts if o.startswith(text)]

            try:
                return options_list[state]
            except IndexError:
                return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t")

    # ── prompt ───────────────────────────────────────────────────
    def _prompt(self) -> str:
        if self.multi_mode:
            count = len(self.queue)
            ctx = f"{M}(multi:{count}){RST}"
        elif self.module:
            ctx = f"{Y}({self.module.name}){RST}"
        else:
            ctx = ""
        return f"{R}{BLD}nmapsh{RST}{ctx}{W} > {RST}"

    # ── main loop ────────────────────────────────────────────────
    def run(self):
        print(BANNER)
        while True:
            try:
                raw = input(self._prompt()).strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{Y}[*] Use 'exit' to quit.{RST}")
                continue

            if not raw:
                continue

            parts = raw.split(None, 2)
            cmd   = parts[0].lower()
            args  = parts[1:] if len(parts) > 1 else []

            # multi-mode-only commands
            if self.multi_mode and cmd in ("add", "remove", "list", "clear_queue"):
                getattr(self, f"cmd_{cmd}")(args)
                continue

            dispatch = {
                "help":       self.cmd_help,
                "?":          self.cmd_help,
                "search":     self.cmd_search,
                "use":        self.cmd_use,
                "show":       self.cmd_show,
                "set":        self.cmd_set,
                "unset":      self.cmd_unset,
                "run":        self.cmd_run,
                "info":       self.cmd_info,
                "back":       self.cmd_back,
                "results":    self.cmd_results,
                "clear":      lambda _: os.system("clear"),
                "exit":       self._exit,
                "quit":       self._exit,
            }

            handler = dispatch.get(cmd)
            if handler:
                handler(args)
            elif cmd in ("add", "remove", "list", "clear_queue"):
                print(f"{Y}[*] '{cmd}' only works in multi mode.  Use: use multi{RST}")
            else:
                print(f"{R}[!] Unknown command: {cmd}  (type 'help'){RST}")

    # ═══════════════════════════════════════════════════════════
    #  STANDARD COMMANDS
    # ═══════════════════════════════════════════════════════════

    def cmd_help(self, args: list[str]):
        if not args:
            print(HELP_MAIN)
            return
        topic = args[0].lower()
        if topic == "modules":
            self._show_all_modules()
        elif topic in HELP_TOPICS:
            print(HELP_TOPICS[topic])
        else:
            print(f"{Y}[*] Unknown help topic: '{topic}'{RST}")
            print(f"    Available: {', '.join(sorted(HELP_TOPICS.keys()))}")

    def cmd_search(self, args: list[str]):
        if not args:
            print(f"{Y}Usage: search <keyword>  |  help search  for keyword ideas{RST}")
            return
        kw      = " ".join(args)
        results = search_modules(kw)
        if not results:
            print(f"{Y}[-] No modules found for: '{kw}'{RST}")
            print(f"    Try: {C}help search{RST} for keyword ideas")
            return
        print(f"\n{BLD}  {'Module':<35} {'Category':<14} Description{RST}")
        print("  " + "─" * 78)
        for m in sorted(results, key=lambda x: x.name):
            root_flag = f" {R}[root]{RST}" if m.requires_root else ""
            print(f"  {G}{m.name:<35}{RST}{C}{m.category:<14}{RST}{m.description}{root_flag}")
        if self.multi_mode:
            print(f"\n  {DIM}Tip: type 'add <module>' to queue it{RST}")
        print()

    def cmd_use(self, args: list[str]):
        if not args:
            print(f"{Y}Usage: use <module_name>  |  use multi{RST}")
            return
        name = args[0]

        if name.lower() == "multi":
            self.multi_mode = True
            self.module     = None
            self.queue      = []
            print(f"\n{M}[+] Multi-module mode activated{RST}")
            print(f"    {C}add <module>{RST}        add a module to the queue")
            print(f"    {C}list{RST}                view the queue")
            print(f"    {C}set target <ip>{RST}     set the target")
            print(f"    {C}run{RST}                 execute all queued modules")
            print(f"    {C}help multi{RST}          full guide + combinations\n")
            return

        mod = get_module(name)
        if not mod:
            close = search_modules(name)
            if close:
                print(f"{Y}[-] Module not found. Did you mean:{RST}")
                for m in close[:5]:
                    print(f"    {G}{m.name}{RST}")
            else:
                print(f"{R}[!] Module '{name}' not found.  Try: search <keyword>{RST}")
            return

        self.multi_mode = False
        self.queue      = []
        self.module     = mod
        print(f"\n{G}[+] Loaded: {BLD}{mod.name}{RST}")
        print(f"    {mod.description}")
        if mod.requires_root:
            print(f"    {R}[!] Requires root/sudo{RST}")
        print(f"\n    {C}set target <ip/cidr>{RST}  then  {C}run{RST}\n")

    def cmd_show(self, args: list[str]):
        sub = args[0].lower() if args else ""
        if sub == "modules":
            self._show_all_modules()
        elif sub == "categories":
            self._show_categories()
        elif sub == "options":
            self._show_options()
        else:
            print(f"{Y}Usage: show [modules | categories | options]{RST}")

    def _show_all_modules(self):
        for cat in list_categories():
            print(f"\n{BLD}{C}  [{cat.upper()}]{RST}")
            print("  " + "─" * 70)
            mods = [m for m in MODULES.values() if m.category == cat]
            for m in sorted(mods, key=lambda x: x.name):
                root = f" {R}*root*{RST}" if m.requires_root else ""
                print(f"  {G}{m.name:<36}{RST}{m.description}{root}")
        print(f"\n  {DIM}*root* = requires sudo{RST}\n")

    def _show_categories(self):
        print(f"\n{BLD}  Categories:{RST}")
        for cat in list_categories():
            count = sum(1 for m in MODULES.values() if m.category == cat)
            print(f"    {C}{cat:<18}{RST} {count} module(s)")
        print()

    def _show_options(self):
        if self.multi_mode:
            print(f"\n{BLD}  Mode :{RST} {M}multi-module{RST}")
            if self.queue:
                print(f"{BLD}  Queue:{RST}")
                for i, m in enumerate(self.queue, 1):
                    root = f" {R}[root]{RST}" if m.requires_root else ""
                    print(f"    {DIM}{i}.{RST} {G}{m.name}{RST}{root}")
            else:
                print(f"{BLD}  Queue:{RST} {DIM}(empty){RST}")
        else:
            if not self.module:
                print(f"{Y}[*] No module loaded.{RST}")
                return
            print(f"\n{BLD}  Module:{RST} {G}{self.module.name}{RST}")
            print(f"{BLD}  Desc  :{RST} {self.module.description}")
            print(f"{BLD}  Args  :{RST} {C}nmap {self.module.nmap_args}{RST}")
            if self.module.requires_root:
                print(f"  {R}[!] Requires root{RST}")

        req_map = {"target": True, "ports": False, "timing": False,
                   "extra": False, "outfile": False}
        print(f"\n{BLD}  {'Option':<12} {'Value':<35} Required{RST}")
        print("  " + "─" * 55)
        for opt, val in self.options.items():
            req  = f"{R}yes{RST}" if req_map.get(opt) else f"{DIM}no{RST}"
            disp = f"{G}{val}{RST}" if val else f"{DIM}(not set){RST}"
            print(f"  {Y}{opt:<12}{RST} {disp:<44} {req}")
        print()

    def cmd_set(self, args: list[str]):
        if len(args) < 2:
            print(f"{Y}Usage: set <option> <value>  |  help set{RST}")
            return
        opt = args[0].lower()
        val = " ".join(args[1:])
        if opt not in self.options:
            print(f"{R}[!] Unknown option '{opt}'. Options: {', '.join(self.options.keys())}{RST}")
            return
        self.options[opt] = val
        print(f"  {G}{opt}{RST} => {C}{val}{RST}")

    def cmd_unset(self, args: list[str]):
        if not args:
            print(f"{Y}Usage: unset <option>{RST}")
            return
        opt = args[0].lower()
        if opt not in self.options:
            print(f"{R}[!] Unknown option '{opt}'{RST}")
            return
        self.options[opt] = ""
        print(f"  {Y}{opt}{RST} cleared.")

    def cmd_run(self, _args):
        if not self.options["target"]:
            print(f"{R}[!] Target not set.  Use: set target <ip/cidr>{RST}")
            return
        if self.multi_mode:
            self._run_multi()
        else:
            self._run_single()

    def _run_single(self):
        if not self.module:
            print(f"{R}[!] No module loaded.  Use: use <module>{RST}")
            return
        cfg = ScanConfig(
            target      = self.options["target"],
            module      = self.module,
            output_base = self.options["outfile"] or None,
            extra_args  = self.options["extra"],
            timing      = self.options["timing"],
            ports       = self.options["ports"],
        )
        print(f"\n{G}[*] Module : {BLD}{self.module.name}{RST}")
        print(f"{G}[*] Target : {BLD}{cfg.target}{RST}")
        rc = run_scan(cfg)
        self._print_rc(rc)

    def _run_multi(self):
        if not self.queue:
            print(f"{R}[!] Queue is empty.  Use: add <module_name>{RST}")
            return

        total = len(self.queue)
        print(f"\n{M}{BLD}[*] Multi-scan — {total} module(s) | target: {self.options['target']}{RST}")
        print("─" * 60)

        passed = 0
        failed = 0

        for idx, mod in enumerate(self.queue, 1):
            print(f"\n{C}{BLD}[{idx}/{total}] {mod.name}{RST}")
            if mod.requires_root:
                print(f"  {R}[!] This module needs root/sudo{RST}")

            base = self.options["outfile"]
            per_mod_base = f"{base}_{mod.name.replace('/', '_')}" if base else None

            cfg = ScanConfig(
                target      = self.options["target"],
                module      = mod,
                output_base = per_mod_base,
                extra_args  = self.options["extra"],
                timing      = self.options["timing"],
                ports       = self.options["ports"],
            )
            rc = run_scan(cfg)

            if rc == 0:
                print(f"{G}  [+] Done: {mod.name}{RST}")
                passed += 1
            elif rc == 130:
                print(f"{Y}  [!] Interrupted — stopping multi-scan.{RST}")
                break
            else:
                print(f"{R}  [x] Failed (exit {rc}): {mod.name}{RST}")
                failed += 1

        print(f"\n{'─'*60}")
        print(f"{M}{BLD}[*] Multi-scan finished{RST}")
        print(f"    {G}Completed : {passed}{RST}")
        if failed:
            print(f"    {R}Failed    : {failed}{RST}")
        print(f"    Files     : {Y}{OUTPUT_DIR}/{RST}")
        print(f"    View      : {C}results{RST}\n")

    def _print_rc(self, rc: int):
        if rc == 0:
            print(f"\n{G}[+] Done. Files saved in: {OUTPUT_DIR}/{RST}\n")
        elif rc == 130:
            print(f"{Y}[*] Scan interrupted.{RST}\n")
        else:
            print(f"{R}[!] Nmap exited with code {rc}{RST}\n")

    def cmd_info(self, _args):
        if self.multi_mode:
            self.cmd_list([]); return
        if not self.module:
            print(f"{Y}[*] No module loaded.{RST}"); return
        m = self.module
        print(f"""
{BLD}{C}Module Information{RST}
  {BLD}Name     :{RST} {G}{m.name}{RST}
  {BLD}Category :{RST} {C}{m.category}{RST}
  {BLD}Requires :{RST} {'root/sudo' if m.requires_root else 'no special privileges'}

{BLD}Description:{RST}
  {m.description}

{BLD}Nmap Arguments:{RST}
  {C}nmap {m.nmap_args} <target>{RST}

{BLD}Example:{RST}
  {DIM}{m.example}{RST}
""")

    def cmd_back(self, _args):
        if self.multi_mode:
            print(f"{Y}[*] Leaving multi mode. Queue cleared.{RST}")
            self.multi_mode = False
            self.queue      = []
        elif self.module:
            print(f"{Y}[*] Unloaded: {self.module.name}{RST}")
            self.module = None
        else:
            print(f"{DIM}[*] Nothing to unload.{RST}")

    def cmd_results(self, _args):
        files = sorted(OUTPUT_DIR.iterdir()) if OUTPUT_DIR.exists() else []
        if not files:
            print(f"{Y}[*] No results yet. Run a scan first.{RST}")
            return
        print(f"\n{BLD}  Saved files  ({OUTPUT_DIR}/){RST}")
        print("  " + "─" * 58)
        for f in files:
            size      = f"{f.stat().st_size / 1024:.1f} KB"
            ext_color = {".xml": G, ".nmap": C, ".gnmap": Y}.get(f.suffix, W)
            print(f"  {ext_color}{f.name:<48}{RST} {DIM}{size}{RST}")
        print()

    def _exit(self, _args=None):
        print(f"\n{Y}[*] Exiting NmapShell. Stay legal. 👋{RST}\n")
        sys.exit(0)

    # ═══════════════════════════════════════════════════════════
    #  MULTI-MODE COMMANDS
    # ═══════════════════════════════════════════════════════════

    def cmd_add(self, args: list[str]):
        if not args:
            print(f"{Y}Usage: add <module_name>  |  search <keyword> to find modules{RST}")
            return
        mod = get_module(args[0])
        if not mod:
            close = search_modules(args[0])
            if close:
                print(f"{Y}[-] Not found. Did you mean:{RST}")
                for m in close[:5]:
                    print(f"    {G}{m.name}{RST}")
            else:
                print(f"{R}[!] Module '{args[0]}' not found.  Try: search <keyword>{RST}")
            return

        if any(m.name == mod.name for m in self.queue):
            print(f"{Y}[*] '{mod.name}' is already in the queue.{RST}")
            return

        self.queue.append(mod)
        root = f"  {R}[needs root]{RST}" if mod.requires_root else ""
        print(f"  {G}[+]{RST} {G}{mod.name}{RST}{root}  "
              f"{DIM}({len(self.queue)} in queue){RST}")

    def cmd_remove(self, args: list[str]):
        if not args:
            print(f"{Y}Usage: remove <module_name>{RST}")
            return
        before     = len(self.queue)
        self.queue = [m for m in self.queue if m.name != args[0]]
        if len(self.queue) < before:
            print(f"  {Y}[-] Removed: {args[0]}{RST}  {DIM}({len(self.queue)} remaining){RST}")
        else:
            print(f"{R}[!] '{args[0]}' not in queue.{RST}")

    def cmd_list(self, _args):
        if not self.queue:
            print(f"\n{Y}  Queue is empty.  Use: add <module_name>{RST}\n")
            return
        print(f"\n{BLD}{M}  Queued modules ({len(self.queue)} total):{RST}")
        print("  " + "─" * 58)
        for i, m in enumerate(self.queue, 1):
            root = f"  {R}[root]{RST}" if m.requires_root else ""
            desc = m.description[:35] + "..." if len(m.description) > 35 else m.description
            print(f"  {DIM}{i:>2}.{RST} {G}{m.name:<35}{RST} {DIM}{desc}{RST}{root}")
        print()
        tgt = self.options["target"]
        if tgt:
            print(f"  {BLD}Target:{RST} {C}{tgt}{RST}")
        else:
            print(f"  {BLD}Target:{RST} {R}(not set -- use: set target <ip>){RST}")
        print()

    def cmd_clear_queue(self, _args):
        if not self.queue:
            print(f"{DIM}[*] Queue already empty.{RST}"); return
        count      = len(self.queue)
        self.queue = []
        print(f"{Y}[*] Queue cleared ({count} module(s) removed).{RST}")
