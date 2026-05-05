"""
shell.py - NmapShell interactive console (Metasploit-style)
v1.2 — number-based module selection + readline prompt width fix
"""

import os
import sys
import readline
from typing import Optional

from modules import MODULES, ScanModule, search_modules, get_module, list_categories
from runner import ScanConfig, run_scan, OUTPUT_DIR

# ── colours for print() ─────────────────────────────────────────
PR  = "\033[31m";  PG  = "\033[32m";  PY  = "\033[33m"
PM  = "\033[35m";  PC  = "\033[36m"
PBLD= "\033[1m";   PDIM= "\033[2m";   PRST= "\033[0m"

# ── colours for input() prompt ──────────────────────────────────
# Wrapping escape codes in \001..\002 tells readline to treat them
# as zero-width.  Without this readline miscounts the prompt length
# and the cursor drifts — causing the text-overlap on split screens.
def _p(c: str) -> str:
    return f"\001{c}\002"

_R = _p("\033[31m"); _G = _p("\033[32m"); _Y = _p("\033[33m")
_M = _p("\033[35m"); _C = _p("\033[36m"); _W = _p("\033[37m")
_B = _p("\033[1m");  _D = _p("\033[2m");  _X = _p("\033[0m")

# ────────────────────────────────────────────────────────────────

BANNER = f"""{PR}{PBLD}
  ███╗   ██╗███╗   ███╗ █████╗ ██████╗ ███████╗██╗  ██╗
  ████╗  ██║████╗ ████║██╔══██╗██╔══██╗██╔════╝██║  ██║
  ██╔██╗ ██║██╔████╔██║███████║██████╔╝███████╗███████║
  ██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ ╚════██║██╔══██║
  ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     ███████║██║  ██║
  ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
{PRST}{PY}  Interactive Nmap Automation Framework{PRST}
  {PDIM}Version 1.2  |  For authorized use only{PRST}

  Type {PC}help{PRST} to get started  |  {PC}use multi{PRST} to run multiple modules at once
  After {PC}search{PRST}, load a result with {PC}use 0{PRST}, {PC}use 1{PRST}, etc.
"""

# ════════════════════════════════════════════════════════════════
#  HELP TEXT  (plain P* colours — safe for print())
# ════════════════════════════════════════════════════════════════

HELP_MAIN = f"""
{PBLD}{PC}+------------------------------------------------------+
|          NmapShell  -  Command Reference             |
+------------------------------------------------------+{PRST}

{PBLD}{PC}HELP TOPICS{PRST}  (type: help <topic>)
  {PG}help search{PRST}      Keyword list for finding modules
  {PG}help set{PRST}         All options explained with examples
  {PG}help modules{PRST}     Full module list
  {PG}help multi{PRST}       How to run multiple modules in one scan
  {PG}help workflow{PRST}    Step-by-step example workflows
  {PG}help targets{PRST}     IP / CIDR / range format guide
  {PG}help timing{PRST}      Timing flags -T0 to -T5 explained
  {PG}help output{PRST}      Output file formats (.nmap .xml .gnmap)

{PBLD}{PC}CORE COMMANDS{PRST}
  {PG}search  <keyword>{PRST}         Search modules by keyword
  {PG}use     <number>{PRST}          Load module by search result number
  {PG}use     <module/name>{PRST}     Load a module by full name
  {PG}use     multi{PRST}             Enter multi-module scan mode
  {PG}show    modules{PRST}           List every module
  {PG}show    categories{PRST}        List module categories
  {PG}show    options{PRST}           Show current options
  {PG}info{PRST}                      Full info on loaded module
  {PG}set     <option> <value>{PRST}  Set an option
  {PG}unset   <option>{PRST}          Clear an option
  {PG}run{PRST}                       Execute the scan
  {PG}results{PRST}                   List saved output files
  {PG}back{PRST}                      Unload module / leave multi mode
  {PG}clear{PRST}                     Clear the screen
  {PG}exit / quit{PRST}               Exit NmapShell

{PBLD}{PC}MULTI-MODULE COMMANDS{PRST}  (only inside 'use multi')
  {PG}add  <number or name>{PRST}     Add a module to the scan queue
  {PG}remove  <module/name>{PRST}     Remove a module from the queue
  {PG}list{PRST}                      Show queued modules
  {PG}clear_queue{PRST}               Remove all modules from queue

  {PDIM}Tip: TAB auto-completes commands and module names{PRST}
"""

HELP_SEARCH = f"""
{PBLD}{PC}SEARCH COMMAND{PRST}
  Usage: {PG}search <keyword>{PRST}
  After searching: {PG}use 0{PRST}, {PG}use 1{PRST}, {PG}use 2{PRST} ... to load a result directly

{PBLD}By service / protocol:{PRST}
  {PY}http{PRST}       HTTP enumeration (titles, methods, dirs)
  {PY}smb{PRST}        SMB/Windows shares, users, security
  {PY}ftp{PRST}        FTP anon login, banner, bounce check
  {PY}ssh{PRST}        SSH host-key, auth methods, algorithms
  {PY}ssl{PRST}        SSL/TLS cert, ciphers, heartbleed
  {PY}dns{PRST}        DNS zone transfer, brute, service info
  {PY}snmp{PRST}       SNMP community string enum
  {PY}vuln{PRST}       Vulnerability detection scripts

{PBLD}By scan type:{PRST}
  {PY}port{PRST}       All port scan modules
  {PY}udp{PRST}        UDP scanning
  {PY}syn{PRST}        SYN stealth scan (requires root)
  {PY}connect{PRST}    TCP connect scan (no root needed)
  {PY}full{PRST}       All 65535 ports
  {PY}quick{PRST}      Fast top-100 ports

{PBLD}By goal:{PRST}
  {PY}discovery{PRST}  Find live hosts on a network
  {PY}version{PRST}    Detect service/software versions
  {PY}os{PRST}         Operating system fingerprinting
  {PY}aggressive{PRST} Full -A scan (OS + version + scripts)
  {PY}banner{PRST}     Grab service banners

{PBLD}By category:{PRST}
  {PY}portscan  discovery  enum  scripts  timing{PRST}
"""

HELP_SET = f"""
{PBLD}{PC}SET COMMAND{PRST}
  Usage: {PG}set <option> <value>{PRST}
  Usage: {PG}unset <option>{PRST}

  {PY}target{PRST}   {PR}(required){PRST}
      {PC}set target 192.168.1.1{PRST}
      {PC}set target 192.168.1.0/24{PRST}
      {PC}set target scanme.nmap.org{PRST}

  {PY}ports{PRST}    {PDIM}(optional - overrides module default){PRST}
      {PC}set ports 80,443{PRST}
      {PC}set ports 1-1024{PRST}
      {PC}set ports -{PRST}          <- all 65535 ports

  {PY}timing{PRST}   {PDIM}(optional){PRST}
      {PC}set timing -T1{PRST}       <- slow / sneaky
      {PC}set timing -T4{PRST}       <- fast / recommended

  {PY}extra{PRST}    {PDIM}(optional - any raw nmap flags){PRST}
      {PC}set extra --open{PRST}
      {PC}set extra -v --open{PRST}

  {PY}outfile{PRST}  {PDIM}(optional - base filename, no extension){PRST}
      {PC}set outfile my_scan{PRST}
      -> saves: my_scan.nmap / my_scan.xml / my_scan.gnmap
"""

HELP_TARGETS = f"""
{PBLD}{PC}TARGET FORMATS{PRST}
  {PC}set target 192.168.1.1{PRST}              Single IP
  {PC}set target 192.168.1.0/24{PRST}           CIDR subnet (256 hosts)
  {PC}set target 10.0.0.0/16{PRST}              Larger subnet
  {PC}set target 192.168.1.1-50{PRST}           IP range (.1 to .50)
  {PC}set target 192.168.1.1 192.168.1.5{PRST}  Multiple IPs
  {PC}set target scanme.nmap.org{PRST}           Hostname
"""

HELP_TIMING = f"""
{PBLD}{PC}TIMING FLAGS  (-T0 to -T5){PRST}
  Use with:  {PG}set timing -T<n>{PRST}

  {PY}-T0{PRST}  Paranoid    One probe every 5 min. Maximum stealth.
  {PY}-T1{PRST}  Sneaky      Very slow. Low IDS detection.
  {PY}-T2{PRST}  Polite      Slower than default. Saves bandwidth.
  {PY}-T3{PRST}  Normal      Default nmap timing.
  {PY}-T4{PRST}  Aggressive  Fast. Good for local networks. {PG}<- Recommended{PRST}
  {PY}-T5{PRST}  Insane      Maximum speed. May miss results.
"""

HELP_OUTPUT = f"""
{PBLD}{PC}OUTPUT FILES  ->  saved in {PY}nmap_results/{PRST}

  {PG}.nmap{PRST}    Human-readable output
  {PG}.xml{PRST}     Machine-parseable XML
  {PG}.gnmap{PRST}   Grepable format

  Files are named:  {PC}<module>_<target>_<timestamp>{PRST}
  View them with:   {PG}results{PRST}

  Grep example (in bash):
    {PDIM}grep "80/open" nmap_results/*.gnmap{PRST}
"""

HELP_MULTI = f"""
{PBLD}{PC}MULTI-MODULE SCAN MODE{PRST}
  Run several modules against the same target in sequence.

{PBLD}Workflow:{PRST}
  {PC}use multi{PRST}
  {PC}add portscan/quick{PRST}          <- by name
  {PC}search http{PRST}
  {PC}add 0{PRST}                       <- by search result number
  {PC}add scripts/ssh{PRST}
  {PC}list{PRST}                        <- review queue
  {PC}set target 192.168.1.1{PRST}
  {PC}run{PRST}                         <- fires all in sequence

{PBLD}Queue commands:{PRST}
  {PG}add <name or number>{PRST}    Add module (duplicates ignored)
  {PG}remove <name>{PRST}           Remove one module
  {PG}list{PRST}                    View queue
  {PG}clear_queue{PRST}             Wipe queue
  {PG}back{PRST}                    Leave multi mode

{PBLD}Useful combinations:{PRST}
  Web server:   portscan/quick + scripts/http + scripts/ssl
  Windows host: portscan/top1000 + scripts/smb + scripts/dns
  Services:     scripts/ftp + scripts/ssh + scripts/http + scripts/smb
"""

HELP_WORKFLOW = f"""
{PBLD}{PC}EXAMPLE WORKFLOWS{PRST}

{PBLD}1. Search and load by number (fastest){PRST}
   {PC}search port{PRST}
   {PC}use 0{PRST}
   {PC}set target 192.168.1.1{PRST}
   {PC}run{PRST}

{PBLD}2. Web server recon (multi){PRST}
   {PC}use multi{PRST}
   {PC}add portscan/quick{PRST}
   {PC}add scripts/http{PRST}
   {PC}add scripts/ssl{PRST}
   {PC}set target 192.168.1.50{PRST}
   {PC}set timing -T4{PRST}
   {PC}run{PRST}

{PBLD}3. Windows / SMB host (multi){PRST}
   {PC}use multi{PRST}
   {PC}add portscan/top1000{PRST}
   {PC}add scripts/smb{PRST}
   {PC}add scripts/dns{PRST}
   {PC}set target 192.168.1.10{PRST}
   {PC}run{PRST}

{PBLD}4. All common services (multi){PRST}
   {PC}use multi{PRST}
   {PC}add scripts/ftp{PRST}
   {PC}add scripts/ssh{PRST}
   {PC}add scripts/http{PRST}
   {PC}add scripts/smb{PRST}
   {PC}add scripts/ssl{PRST}
   {PC}set target 10.10.10.5{PRST}
   {PC}set timing -T4{PRST}
   {PC}run{PRST}
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

# ════════════════════════════════════════════════════════════════
#  SHELL
# ════════════════════════════════════════════════════════════════

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
        # last search results — enables 'use 0', 'use 1', 'add 0' etc.
        self.last_results: list[ScanModule] = []
        self._setup_readline()

    # ── readline tab completion ──────────────────────────────────
    def _setup_readline(self):
        base_cmds  = ["search ", "use ", "show ", "set ", "unset ",
                      "run", "info", "back", "results", "clear",
                      "help ", "exit", "quit"]
        multi_cmds = ["add ", "remove ", "list", "clear_queue"]
        show_opts  = ["modules", "categories", "options"]
        set_opts   = ["target ", "ports ", "timing ", "extra ", "outfile "]
        help_opts  = list(HELP_TOPICS.keys())
        mod_names  = list(MODULES.keys())

        def completer(text, state):
            buf   = readline.get_line_buffer().lstrip()
            parts = buf.split()
            first = parts[0].lower() if parts else ""
            opts: list[str] = []

            if len(parts) == 0 or (len(parts) == 1 and not buf.endswith(" ")):
                cmds = base_cmds + multi_cmds if self.multi_mode else base_cmds
                opts = [c for c in cmds if c.startswith(text)]
            elif first in ("use", "add", "remove"):
                opts = [m for m in mod_names if m.startswith(text)]
                if first == "use" and "multi".startswith(text):
                    opts = ["multi"] + opts
            elif first == "show":
                opts = [o for o in show_opts if o.startswith(text)]
            elif first in ("help", "?"):
                opts = [o for o in help_opts if o.startswith(text)]
            elif first == "set":
                opts = [o for o in set_opts if o.startswith(text)]

            try:
                return opts[state]
            except IndexError:
                return None

        readline.set_completer(completer)
        readline.parse_and_bind("tab: complete")
        readline.set_completer_delims(" \t")

    # ── prompt  (uses _rl-wrapped codes for correct width) ───────
    def _prompt(self) -> str:
        if self.multi_mode:
            ctx = f"{_M}(multi:{len(self.queue)}){_X}"
        elif self.module:
            ctx = f"{_Y}({self.module.name}){_X}"
        else:
            ctx = ""
        return f"{_R}{_B}nmapsh{_X}{ctx}{_W} > {_X}"

    # ── main loop ────────────────────────────────────────────────
    def run(self):
        print(BANNER)
        while True:
            try:
                raw = input(self._prompt()).strip()
            except (KeyboardInterrupt, EOFError):
                print(f"\n{PY}[*] Use 'exit' to quit.{PRST}")
                continue
            if not raw:
                continue

            parts = raw.split(None, 2)
            cmd   = parts[0].lower()
            args  = parts[1:] if len(parts) > 1 else []

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
                print(f"{PY}[*] '{cmd}' only works in multi mode.  Use: use multi{PRST}")
            else:
                print(f"{PR}[!] Unknown command: {cmd}  (type 'help'){PRST}")

    # ════════════════════════════════════════════════════════════
    #  HELPERS
    # ════════════════════════════════════════════════════════════

    def _resolve_module(self, token: str) -> Optional[ScanModule]:
        """
        Resolve a module from either:
          - a number  -> index into last_results  (0-based)
          - a name    -> direct MODULES lookup
        Returns None and prints an error if not found.
        """
        if token.isdigit():
            idx = int(token)
            if not self.last_results:
                print(f"{PR}[!] No search results to index.  Run 'search <keyword>' first.{PRST}")
                return None
            if idx >= len(self.last_results):
                print(f"{PR}[!] Index {idx} out of range.  "
                      f"Last search had {len(self.last_results)} result(s) (0-{len(self.last_results)-1}).{PRST}")
                return None
            return self.last_results[idx]

        mod = get_module(token)
        if not mod:
            close = search_modules(token)
            if close:
                print(f"{PY}[-] Module not found. Did you mean:{PRST}")
                for m in close[:5]:
                    print(f"    {PG}{m.name}{PRST}")
            else:
                print(f"{PR}[!] Module '{token}' not found.  Try: search <keyword>{PRST}")
        return mod

    # ════════════════════════════════════════════════════════════
    #  COMMANDS
    # ════════════════════════════════════════════════════════════

    def cmd_help(self, args: list[str]):
        if not args:
            print(HELP_MAIN); return
        topic = args[0].lower()
        if topic == "modules":
            self._show_all_modules()
        elif topic in HELP_TOPICS:
            print(HELP_TOPICS[topic])
        else:
            print(f"{PY}[*] Unknown topic: '{topic}'{PRST}")
            print(f"    Available: {', '.join(sorted(HELP_TOPICS.keys()))}")

    def cmd_search(self, args: list[str]):
        if not args:
            print(f"{PY}Usage: search <keyword>  |  help search  for ideas{PRST}")
            return
        kw      = " ".join(args)
        results = sorted(search_modules(kw), key=lambda x: x.name)
        if not results:
            print(f"{PY}[-] No modules found for '{kw}'.  Try: help search{PRST}")
            self.last_results = []
            return

        # store so 'use 0', 'add 0', etc. work immediately
        self.last_results = results

        print(f"\n{PBLD}  {'#':<4} {'Module':<35} {'Category':<14} Description{PRST}")
        print("  " + "-" * 80)
        for i, m in enumerate(results):
            root = f"  {PR}[root]{PRST}" if m.requires_root else ""
            print(f"  {PC}{i:<4}{PRST}{PG}{m.name:<35}{PRST}{PDIM}{m.category:<14}{PRST}"
                  f"{m.description}{root}")

        hint = "use" if not self.multi_mode else "add"
        print(f"\n  {PDIM}Load with: {hint} 0  /  {hint} 1  /  {hint} 2 ...{PRST}\n")

    def cmd_use(self, args: list[str]):
        if not args:
            print(f"{PY}Usage: use <number> | use <module/name> | use multi{PRST}")
            return
        token = args[0]

        if token.lower() == "multi":
            self.multi_mode = True
            self.module     = None
            self.queue      = []
            print(f"\n{PM}[+] Multi-module mode{PRST}")
            print(f"    {PC}add <module or number>{PRST}   add to queue")
            print(f"    {PC}list{PRST}                     view queue")
            print(f"    {PC}set target <ip>{PRST}          set target")
            print(f"    {PC}run{PRST}                      execute all\n")
            return

        mod = self._resolve_module(token)
        if not mod:
            return

        self.multi_mode = False
        self.queue      = []
        self.module     = mod
        print(f"\n{PG}[+] Loaded: {PBLD}{mod.name}{PRST}")
        print(f"    {mod.description}")
        if mod.requires_root:
            print(f"    {PR}[!] Requires root/sudo{PRST}")
        print(f"\n    {PC}set target <ip/cidr>{PRST}  then  {PC}run{PRST}\n")

    def cmd_show(self, args: list[str]):
        sub = args[0].lower() if args else ""
        if sub == "modules":
            self._show_all_modules()
        elif sub == "categories":
            self._show_categories()
        elif sub == "options":
            self._show_options()
        else:
            print(f"{PY}Usage: show [modules | categories | options]{PRST}")

    def _show_all_modules(self):
        for cat in list_categories():
            print(f"\n{PBLD}{PC}  [{cat.upper()}]{PRST}")
            print("  " + "-" * 70)
            for m in sorted((m for m in MODULES.values() if m.category == cat),
                            key=lambda x: x.name):
                root = f"  {PR}*root*{PRST}" if m.requires_root else ""
                print(f"  {PG}{m.name:<36}{PRST}{m.description}{root}")
        print(f"\n  {PDIM}*root* = requires sudo{PRST}\n")

    def _show_categories(self):
        print(f"\n{PBLD}  Categories:{PRST}")
        for cat in list_categories():
            count = sum(1 for m in MODULES.values() if m.category == cat)
            print(f"    {PC}{cat:<18}{PRST} {count} module(s)")
        print()

    def _show_options(self):
        if self.multi_mode:
            print(f"\n{PBLD}  Mode :{PRST} {PM}multi-module{PRST}")
            if self.queue:
                print(f"{PBLD}  Queue:{PRST}")
                for i, m in enumerate(self.queue, 1):
                    root = f"  {PR}[root]{PRST}" if m.requires_root else ""
                    print(f"    {PDIM}{i}.{PRST} {PG}{m.name}{PRST}{root}")
            else:
                print(f"{PBLD}  Queue:{PRST} {PDIM}(empty){PRST}")
        else:
            if not self.module:
                print(f"{PY}[*] No module loaded.{PRST}"); return
            print(f"\n{PBLD}  Module:{PRST} {PG}{self.module.name}{PRST}")
            print(f"{PBLD}  Desc  :{PRST} {self.module.description}")
            print(f"{PBLD}  Args  :{PRST} {PC}nmap {self.module.nmap_args}{PRST}")
            if self.module.requires_root:
                print(f"  {PR}[!] Requires root{PRST}")

        req = {"target": True, "ports": False, "timing": False,
               "extra": False, "outfile": False}
        print(f"\n{PBLD}  {'Option':<12} {'Value':<35} Required{PRST}")
        print("  " + "-" * 55)
        for opt, val in self.options.items():
            r    = f"{PR}yes{PRST}" if req.get(opt) else f"{PDIM}no{PRST}"
            disp = f"{PG}{val}{PRST}" if val else f"{PDIM}(not set){PRST}"
            print(f"  {PY}{opt:<12}{PRST} {disp:<44} {r}")
        print()

    def cmd_set(self, args: list[str]):
        if len(args) < 2:
            print(f"{PY}Usage: set <option> <value>  |  help set{PRST}"); return
        opt = args[0].lower()
        val = " ".join(args[1:])
        if opt not in self.options:
            print(f"{PR}[!] Unknown option '{opt}'. "
                  f"Options: {', '.join(self.options.keys())}{PRST}"); return
        self.options[opt] = val
        print(f"  {PG}{opt}{PRST} => {PC}{val}{PRST}")

    def cmd_unset(self, args: list[str]):
        if not args:
            print(f"{PY}Usage: unset <option>{PRST}"); return
        opt = args[0].lower()
        if opt not in self.options:
            print(f"{PR}[!] Unknown option '{opt}'{PRST}"); return
        self.options[opt] = ""
        print(f"  {PY}{opt}{PRST} cleared.")

    def cmd_run(self, _args):
        if not self.options["target"]:
            print(f"{PR}[!] Target not set.  Use: set target <ip/cidr>{PRST}"); return
        self._run_multi() if self.multi_mode else self._run_single()

    def _run_single(self):
        if not self.module:
            print(f"{PR}[!] No module loaded.  Use: use <module>{PRST}"); return
        cfg = ScanConfig(
            target      = self.options["target"],
            module      = self.module,
            output_base = self.options["outfile"] or None,
            extra_args  = self.options["extra"],
            timing      = self.options["timing"],
            ports       = self.options["ports"],
        )
        print(f"\n{PG}[*] Module : {PBLD}{self.module.name}{PRST}")
        print(f"{PG}[*] Target : {PBLD}{cfg.target}{PRST}")
        self._print_rc(run_scan(cfg))

    def _run_multi(self):
        if not self.queue:
            print(f"{PR}[!] Queue is empty.  Use: add <module>{PRST}"); return
        total = len(self.queue)
        print(f"\n{PM}{PBLD}[*] Multi-scan — {total} module(s) | "
              f"target: {self.options['target']}{PRST}")
        print("-" * 60)
        passed = failed = 0
        for idx, mod in enumerate(self.queue, 1):
            print(f"\n{PC}{PBLD}[{idx}/{total}] {mod.name}{PRST}")
            if mod.requires_root:
                print(f"  {PR}[!] Needs root/sudo{PRST}")
            base = self.options["outfile"]
            cfg = ScanConfig(
                target      = self.options["target"],
                module      = mod,
                output_base = f"{base}_{mod.name.replace('/', '_')}" if base else None,
                extra_args  = self.options["extra"],
                timing      = self.options["timing"],
                ports       = self.options["ports"],
            )
            rc = run_scan(cfg)
            if rc == 0:
                print(f"{PG}  [+] Done: {mod.name}{PRST}"); passed += 1
            elif rc == 130:
                print(f"{PY}  [!] Interrupted — stopping.{PRST}"); break
            else:
                print(f"{PR}  [x] Failed (exit {rc}): {mod.name}{PRST}"); failed += 1

        print(f"\n{'-'*60}")
        print(f"{PM}{PBLD}[*] Multi-scan complete{PRST}")
        print(f"    {PG}Done   : {passed}{PRST}")
        if failed:
            print(f"    {PR}Failed : {failed}{PRST}")
        print(f"    Files  : {PY}{OUTPUT_DIR}/{PRST}")
        print(f"    View   : {PC}results{PRST}\n")

    def _print_rc(self, rc: int):
        if rc == 0:
            print(f"\n{PG}[+] Done. Files saved in: {OUTPUT_DIR}/{PRST}\n")
        elif rc == 130:
            print(f"{PY}[*] Interrupted.{PRST}\n")
        else:
            print(f"{PR}[!] Nmap exited with code {rc}{PRST}\n")

    def cmd_info(self, _args):
        if self.multi_mode:
            self.cmd_list([]); return
        if not self.module:
            print(f"{PY}[*] No module loaded.{PRST}"); return
        m = self.module
        print(f"""
{PBLD}{PC}Module Information{PRST}
  {PBLD}Name     :{PRST} {PG}{m.name}{PRST}
  {PBLD}Category :{PRST} {PC}{m.category}{PRST}
  {PBLD}Requires :{PRST} {'root/sudo' if m.requires_root else 'no special privileges'}

{PBLD}Description:{PRST}
  {m.description}

{PBLD}Nmap Arguments:{PRST}
  {PC}nmap {m.nmap_args} <target>{PRST}

{PBLD}Example:{PRST}
  {PDIM}{m.example}{PRST}
""")

    def cmd_back(self, _args):
        if self.multi_mode:
            print(f"{PY}[*] Leaving multi mode. Queue cleared.{PRST}")
            self.multi_mode = False; self.queue = []
        elif self.module:
            print(f"{PY}[*] Unloaded: {self.module.name}{PRST}")
            self.module = None
        else:
            print(f"{PDIM}[*] Nothing to unload.{PRST}")

    def cmd_results(self, _args):
        files = sorted(OUTPUT_DIR.iterdir()) if OUTPUT_DIR.exists() else []
        if not files:
            print(f"{PY}[*] No results yet. Run a scan first.{PRST}"); return
        print(f"\n{PBLD}  Saved files  ({OUTPUT_DIR}/){PRST}")
        print("  " + "-" * 58)
        for f in files:
            size = f"{f.stat().st_size / 1024:.1f} KB"
            col  = {".xml": PG, ".nmap": PC, ".gnmap": PY}.get(f.suffix, "")
            print(f"  {col}{f.name:<48}{PRST} {PDIM}{size}{PRST}")
        print()

    def _exit(self, _args=None):
        print(f"\n{PY}[*] Exiting NmapShell. Stay legal.{PRST}\n")
        sys.exit(0)

    # ════════════════════════════════════════════════════════════
    #  MULTI-MODE COMMANDS
    # ════════════════════════════════════════════════════════════

    def cmd_add(self, args: list[str]):
        if not args:
            print(f"{PY}Usage: add <number or module_name>{PRST}"); return
        mod = self._resolve_module(args[0])
        if not mod:
            return
        if any(m.name == mod.name for m in self.queue):
            print(f"{PY}[*] '{mod.name}' is already queued.{PRST}"); return
        self.queue.append(mod)
        root = f"  {PR}[needs root]{PRST}" if mod.requires_root else ""
        print(f"  {PG}[+]{PRST} {PG}{mod.name}{PRST}{root}  "
              f"{PDIM}({len(self.queue)} in queue){PRST}")

    def cmd_remove(self, args: list[str]):
        if not args:
            print(f"{PY}Usage: remove <module_name>{PRST}"); return
        before     = len(self.queue)
        self.queue = [m for m in self.queue if m.name != args[0]]
        if len(self.queue) < before:
            print(f"  {PY}[-] Removed: {args[0]}{PRST}  "
                  f"{PDIM}({len(self.queue)} remaining){PRST}")
        else:
            print(f"{PR}[!] '{args[0]}' not in queue.{PRST}")

    def cmd_list(self, _args):
        if not self.queue:
            print(f"\n{PY}  Queue is empty.  Use: add <module>{PRST}\n"); return
        print(f"\n{PBLD}{PM}  Queued ({len(self.queue)} modules):{PRST}")
        print("  " + "-" * 58)
        for i, m in enumerate(self.queue, 1):
            root = f"  {PR}[root]{PRST}" if m.requires_root else ""
            desc = m.description[:38] + "..." if len(m.description) > 38 else m.description
            print(f"  {PDIM}{i:>2}.{PRST} {PG}{m.name:<35}{PRST} {PDIM}{desc}{PRST}{root}")
        tgt = self.options["target"]
        print(f"\n  {PBLD}Target:{PRST} "
              + (f"{PC}{tgt}{PRST}" if tgt else f"{PR}(not set){PRST}"))
        print()

    def cmd_clear_queue(self, _args):
        if not self.queue:
            print(f"{PDIM}[*] Queue already empty.{PRST}"); return
        n = len(self.queue); self.queue = []
        print(f"{PY}[*] Cleared {n} module(s) from queue.{PRST}")
