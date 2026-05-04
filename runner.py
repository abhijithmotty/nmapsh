"""
runner.py — builds and executes Nmap commands, saves output files
"""

import os
import subprocess
import shutil
import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from modules import ScanModule


OUTPUT_DIR = Path("nmap_results")


@dataclass
class ScanConfig:
    target: str
    module: ScanModule
    output_base: Optional[str] = None        # base filename (no extension)
    extra_args: str = ""                     # user-appended args
    save_xml: bool = True
    save_normal: bool = True
    save_grepable: bool = True
    timing: str = ""                         # override timing, e.g. -T4
    ports: str = ""                          # override ports, e.g. -p 80,443


def ensure_output_dir() -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR


def build_command(cfg: ScanConfig) -> tuple[list[str], Path]:
    """Return (argv_list, output_base_path)."""
    ensure_output_dir()

    # ── output filename ──────────────────────────────────────────
    if cfg.output_base:
        base_name = cfg.output_base
    else:
        safe_target = cfg.target.replace("/", "_").replace(":", "_")
        safe_module = cfg.module.name.replace("/", "_")
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"{safe_module}_{safe_target}_{ts}"

    out_path = OUTPUT_DIR / base_name

    # ── build argv ──────────────────────────────────────────────
    cmd = ["nmap"]

    # module base args
    if cfg.module.nmap_args.strip():
        cmd += cfg.module.nmap_args.split()

    # port override
    if cfg.ports:
        cmd += ["-p", cfg.ports]

    # timing override
    if cfg.timing:
        cmd.append(cfg.timing)

    # output formats
    fmt_flags: list[str] = []
    if cfg.save_xml and cfg.save_normal and cfg.save_grepable:
        fmt_flags = ["-oA", str(out_path)]
    else:
        if cfg.save_normal:
            fmt_flags += ["-oN", f"{out_path}.nmap"]
        if cfg.save_xml:
            fmt_flags += ["-oX", f"{out_path}.xml"]
        if cfg.save_grepable:
            fmt_flags += ["-oG", f"{out_path}.gnmap"]

    cmd += fmt_flags

    # extra user args
    if cfg.extra_args.strip():
        cmd += cfg.extra_args.split()

    # target last
    cmd.append(cfg.target)

    return cmd, out_path


def check_nmap() -> bool:
    return shutil.which("nmap") is not None


def run_scan(cfg: ScanConfig) -> int:
    """
    Execute the scan. Streams output live to terminal.
    Returns nmap exit code.
    """
    if not check_nmap():
        print("\n[!] nmap not found in PATH. Please install nmap first.\n")
        return 1

    cmd, out_path = build_command(cfg)

    print(f"\n[*] Command  : {' '.join(cmd)}")
    print(f"[*] Saving to: {out_path}.*\n")
    print("─" * 60)

    try:
        result = subprocess.run(cmd, text=True)
        return result.returncode
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user.\n")
        return 130
    except Exception as e:
        print(f"\n[!] Error running nmap: {e}\n")
        return 1


def list_saved_scans() -> list[Path]:
    """Return unique basenames of saved scans (grouped by stem)."""
    ensure_output_dir()
    stems: set[str] = set()
    files: list[Path] = []
    for f in sorted(OUTPUT_DIR.iterdir()):
        stem = f.stem.rstrip(".")
        if stem not in stems:
            stems.add(stem)
            files.append(f)
    return files
