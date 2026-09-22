"""Shared helpers for the ttd-capa wrapper scripts.

Locating the native binaries, running capa-cpp, and parsing TTD positions live here so the
logic stays in one place instead of drifting across ttd-capa.py / ttd-timeline.py /
ttd-report.py.
"""
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional

# The scripts (and this module) live in the repo root, so binary locations are resolved
# relative to here.
HERE = Path(__file__).resolve().parent

# A position past anything real, so items without a TTD position sort last.
NO_POS_KEY = (1 << 64, 1 << 64)


def find_extractor(explicit: Optional[str]) -> Path:
    """Locate ttdcapa-extract.exe. Exits if it cannot be found."""
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            sys.exit(f"extractor not found: {p}")
        return p
    candidates = [
        HERE / "ttdcapa-extract.exe",
        HERE / "ttd" / "bin" / "x64" / "Release" / "ttdcapa-extract.exe",
        HERE / "ttd" / "bin" / "x64" / "Debug" / "ttdcapa-extract.exe",
    ]
    for c in candidates:
        if c.is_file():
            return c
    found = shutil.which("ttdcapa-extract")
    if found:
        return Path(found)
    sys.exit("could not locate ttdcapa-extract.exe; build the ttd/ project or pass --extractor <path>")


def find_capa_cpp(explicit: Optional[str]) -> Path:
    """Locate capa-cpp.exe (the matcher). Exits if it cannot be found."""
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            sys.exit(f"capa-cpp not found: {p}")
        return p
    # A copy next to the scripts wins outright -- it is the only one placed deliberately.
    beside = HERE / "capa-cpp.exe"
    if beside.is_file():
        return beside
    # Otherwise the exe built inside the capa-cpp/ submodule. Its vcxproj has emitted to
    # several different directories over time (the solution's root-level x64\, the nested
    # per-project x64\, and now build\), and MSBuild leaves the older ones in place. Picking
    # by list order would hand back whichever layout an old build happened to use, so choose
    # the most recently written instead: after a rebuild that is always the current one.
    roots = [HERE / "capa-cpp", HERE / "capa-cpp" / "capa-cpp"]
    candidates = [
        root / out_dir / config / "capa-cpp.exe"
        for root in roots
        for out_dir in ("build", "x64")
        for config in ("Release", "Debug")
    ]
    built = [c for c in candidates if c.is_file()]
    if built:
        return max(built, key=lambda p: p.stat().st_mtime)
    found = shutil.which("capa-cpp")
    if found:
        return Path(found)
    sys.exit(
        "could not locate capa-cpp.exe; build the capa-cpp/ submodule "
        "(see its README) or pass --capa-cpp <path>"
    )


def run_capa_cpp_json(capa_cpp: Path, report_path: Path, rules_path: Path,
                      log_prefix: str = "ttd") -> dict:
    """Run capa-cpp `-j` over the report and return the parsed ResultDocument."""
    cmd = [str(capa_cpp), str(report_path), "-r", str(rules_path), "-j"]
    print(f"[{log_prefix}] matching: {' '.join(cmd)}", file=sys.stderr)
    proc = subprocess.run(cmd, capture_output=True)
    if proc.returncode != 0:
        sys.stderr.buffer.write(proc.stderr)
        sys.exit(f"capa-cpp failed (exit {proc.returncode})")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.exit(f"could not parse capa-cpp JSON output: {e}")


def position_key_from_pos(position: str) -> tuple[int, int]:
    """Sort key from a navigable TTD position 'Sequence:Steps' (hex)."""
    if position and ":" in position:
        seq, _, steps = position.partition(":")
        try:
            return (int(seq, 16), int(steps, 16))
        except ValueError:
            pass
    return NO_POS_KEY
