"""
One-command CAPA-over-TTD wrapper.

Runs the native ttdcapa-extract.exe to turn a .run trace into a neutral TTD report
JSON, then matches capa rules against that report with capa-cpp (the C++
reimplementation of capa's TTD backend, vendored as the `capa-cpp/` submodule).

    python ttd-capa.py <trace.run> <rules-dir> [--sample sample.exe]
                       [--extractor path\\to\\ttdcapa-extract.exe]
                       [--capa-cpp path\\to\\capa-cpp.exe]
                       [--keep-json] [-- capa-cpp args...]

Anything after a bare `--` (or any unrecognized flags) is forwarded to capa-cpp, e.g.:

    python ttd-capa.py trace.run ./rules -- -vv

Assembly (static) scanning
--------------------------
`--scan-code` additionally reconstructs the executable memory regions the program
created at runtime (unpacked / JIT'd / injected code) and runs capa-cpp's *static*
analysis over each, surfacing code-structure capabilities the call-based report cannot
see. `--code-only` does just that pass and skips the dynamic run:

    python ttd-capa.py trace.run ./rules --scan-code
    python ttd-capa.py trace.run ./rules --code-only --keep-dumps
"""
import os
import sys
import shutil
import argparse
import tempfile
import subprocess
from pathlib import Path

from ttd_common import find_extractor, find_capa_cpp

HERE = Path(__file__).resolve().parent


def dynamic_extract_cmd(args, extractor: Path, trace: Path, out_path: Path) -> list[str]:
    """Build the ttdcapa-extract command for a dynamic (API-call) report."""
    cmd = [str(extractor), str(trace), "-o", str(out_path)]
    if args.sample:
        cmd += ["--sample", args.sample]
    if args.max_calls:
        cmd += ["--max-calls", str(args.max_calls)]
    if args.with_stack_args:
        cmd += ["--with-stack-args"]
    if args.win32_index:
        cmd += ["--win32-index", args.win32_index]
    if args.no_metadata:
        cmd += ["--no-metadata"]
    if args.max_buffer:
        cmd += ["--max-buffer", str(args.max_buffer)]
    if args.recover_strings:
        cmd += ["--recover-strings"]
    if args.rebuild_index:
        cmd += ["--rebuild-index"]
    return cmd


def scan_code_extract_cmd(args, extractor: Path, trace: Path, work_dir: Path,
                          manifest_path: Path) -> list[str]:
    """Build the ttdcapa-extract command that reconstructs executable regions."""
    cmd = [
        str(extractor), str(trace), "--scan-code",
        "--dump-dir", str(work_dir),
        "--code-manifest", str(manifest_path),
        "--max-code-scans", str(args.max_code_scans),
    ]
    if args.scan_data:
        cmd += ["--scan-data"]
    if args.no_scan_modules:
        cmd += ["--no-scan-modules"]
    if args.max_region_bytes:
        cmd += ["--max-region-bytes", args.max_region_bytes]
    if args.max_write_log_bytes:
        cmd += ["--max-write-log-bytes", args.max_write_log_bytes]
    if args.rebuild_index:
        cmd += ["--rebuild-index"]
    return cmd


def run_dynamic(args, extractor: Path, capa_cpp: Path, trace: Path, rules: Path,
                capa_extra: list[str]) -> int:
    """Extract a call report, then match capa rules over it with capa-cpp."""
    # --json-output picks a stable path (and keeps it); otherwise a temp file that is kept
    # only with --keep-json (and its path is printed to stderr).
    if args.json_output:
        json_path = Path(args.json_output).resolve()
        json_path.parent.mkdir(parents=True, exist_ok=True)
        keep = True
    else:
        fd, tmp = tempfile.mkstemp(suffix=".ttd.json")
        os.close(fd)
        json_path = Path(tmp)
        keep = args.keep_json

    try:
        extract_cmd = dynamic_extract_cmd(args, extractor, trace, json_path)
        print(f"[ttd-capa] extracting: {' '.join(extract_cmd)}", file=sys.stderr)
        rc = subprocess.call(extract_cmd)
        if rc != 0:
            sys.exit(f"ttdcapa-extract failed (exit {rc})")
        if json_path.stat().st_size == 0:
            sys.exit("ttdcapa-extract produced an empty report")

        # capa-cpp reads the same TTD report; -f ttd is accepted and ignored by it.
        match_cmd = [str(capa_cpp), str(json_path), "-r", str(rules), *capa_extra]
        print(f"[ttd-capa] running capa-cpp: {' '.join(match_cmd)}", file=sys.stderr)
        return subprocess.call(match_cmd)
    finally:
        if keep:
            print(f"[ttd-capa] kept TTD report: {json_path}", file=sys.stderr)
        else:
            json_path.unlink(missing_ok=True)


def run_code_scan(args, extractor: Path, capa_cpp: Path, trace: Path, rules: Path) -> int:
    """Assembly path: reconstruct executable regions, then capa-cpp-static each snapshot.

    With --code-hits-output, additionally replays the trace with execute watchpoints on the
    matched instruction VAs so ttd-timeline.py can position each code capability at the moment
    it actually ran (see --code-hits there).
    """
    work_dir = Path(tempfile.mkdtemp(prefix="ttdcapa-code-"))
    manifest_path = work_dir / "manifest.json"

    # We need the records (which carry the matched VAs) on disk if the user wants a hit trace,
    # even when they didn't ask to keep them.
    if args.code_output:
        code_caps_path = Path(args.code_output).resolve()
    elif args.code_hits_output:
        code_caps_path = work_dir / "code-caps.json"
    else:
        code_caps_path = None

    try:
        extract_cmd = scan_code_extract_cmd(args, extractor, trace, work_dir, manifest_path)
        print(f"[ttd-capa] reconstructing code regions: {' '.join(extract_cmd)}", file=sys.stderr)
        rc = subprocess.call(extract_cmd)
        if rc != 0:
            print(f"[ttd-capa] ttdcapa-extract --scan-code failed (exit {rc})", file=sys.stderr)
            return rc
        if not manifest_path.is_file():
            print("[ttd-capa] no manifest produced by --scan-code", file=sys.stderr)
            return 3

        scan_cmd = [
            str(capa_cpp), "--scan-code-manifest", str(manifest_path),
            "-r", str(rules), "--dumps-dir", str(work_dir),
        ]
        if code_caps_path:
            scan_cmd += ["-o", str(code_caps_path)]
        print(f"[ttd-capa] running static scan: {' '.join(scan_cmd)}", file=sys.stderr)
        rc = subprocess.call(scan_cmd)

        # Optional: trace when each matched code site actually executed, for the timeline.
        if args.code_hits_output and code_caps_path and code_caps_path.is_file():
            hits_cmd = [
                str(extractor), str(trace),
                "--trace-code-hits", str(code_caps_path),
                "--hits-output", str(Path(args.code_hits_output).resolve()),
            ]
            if args.hit_gap is not None:
                hits_cmd += ["--hit-gap", str(args.hit_gap)]
            if args.hit_dedup:
                hits_cmd += ["--hit-dedup", args.hit_dedup]
            print(f"[ttd-capa] tracing code execution hits: {' '.join(hits_cmd)}", file=sys.stderr)
            subprocess.call(hits_cmd)

        return rc
    finally:
        if args.keep_dumps:
            print(f"[ttd-capa] kept reconstructed snapshots in: {work_dir}", file=sys.stderr)
        else:
            shutil.rmtree(work_dir, ignore_errors=True)


def run_summary(args, extractor: Path, capa_cpp: Path, trace: Path, rules: Path) -> int:
    """Run both passes to temp artifacts and print one unified capability report."""
    work = Path(tempfile.mkdtemp(prefix="ttdcapa-summary-"))
    report_json = work / "report.ttd.json"
    manifest_path = work / "manifest.json"
    code_caps = Path(args.code_output).resolve() if args.code_output else (work / "code-caps.json")

    try:
        # 1) dynamic report
        dcmd = dynamic_extract_cmd(args, extractor, trace, report_json)
        print(f"[ttd-capa] extracting (dynamic): {' '.join(dcmd)}", file=sys.stderr)
        if subprocess.call(dcmd) != 0 or not report_json.is_file() or report_json.stat().st_size == 0:
            sys.exit("ttdcapa-extract failed to produce a dynamic report")

        # 2) reconstruct executable regions and static-scan them (best effort: a trace with
        #    no runtime-created code just yields a dynamic-only summary)
        have_code = False
        scmd = scan_code_extract_cmd(args, extractor, trace, work, manifest_path)
        print(f"[ttd-capa] reconstructing code regions: {' '.join(scmd)}", file=sys.stderr)
        if subprocess.call(scmd) == 0 and manifest_path.is_file():
            capa_scan = [
                str(capa_cpp), "--scan-code-manifest", str(manifest_path),
                "-r", str(rules), "--dumps-dir", str(work),
                "-o", str(code_caps), "--quiet",
            ]
            print(f"[ttd-capa] static scan: {' '.join(capa_scan)}", file=sys.stderr)
            # suppress capa-cpp's per-region table; the unified report carries the detail
            subprocess.call(capa_scan, stdout=subprocess.DEVNULL)
            have_code = code_caps.is_file()
        else:
            print("[ttd-capa] no reconstructable code regions; dynamic-only summary", file=sys.stderr)

        # 3) render the unified report
        report_cmd = [
            sys.executable, str(HERE / "ttd-report.py"),
            str(report_json), "-r", str(rules), "--capa-cpp", str(capa_cpp),
        ]
        if have_code:
            report_cmd += ["--code", str(code_caps)]
        print(f"[ttd-capa] building unified report: {' '.join(report_cmd)}", file=sys.stderr)
        return subprocess.call(report_cmd)
    finally:
        if args.keep_json or args.keep_dumps:
            print(f"[ttd-capa] kept summary artifacts in: {work}", file=sys.stderr)
        else:
            shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run CAPA capability detection over a TTD .run trace.",
        epilog="Arguments after `--` are passed through to capa-cpp.",
    )
    parser.add_argument("trace", help="path to the TTD .run trace file")
    parser.add_argument("rules", help="path to a directory of capa rules")
    parser.add_argument("--sample", help="optional on-disk sample for accurate hashes")
    parser.add_argument("--extractor", help="path to ttdcapa-extract.exe")
    parser.add_argument("--capa-cpp", help="path to capa-cpp.exe (default: auto-locate in capa-cpp/ or PATH)")
    parser.add_argument("--max-calls", type=int, help="cap recorded API calls (for huge traces)")
    parser.add_argument(
        "--with-stack-args",
        action="store_true",
        help="for calls with no Win32 metadata, also grab four stack slots past the "
        "register args (calls we have a signature for always capture their true arity)",
    )
    parser.add_argument("--win32-index", help="path to win32-index.bin (default: next to the extractor)")
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="disable metadata-driven argument decoding entirely",
    )
    parser.add_argument("--max-buffer", type=int, help="bytes kept from any one captured buffer (default 256)")
    parser.add_argument(
        "--recover-strings",
        action="store_true",
        help="also run the seeking pass that re-reads the last few string arguments the sweep "
        "could not read; slow (it dominates extraction) but worth it when a rule hinges on a "
        "string (the free recovery at each call's return always runs)",
    )
    parser.add_argument("--keep-json", action="store_true", help="keep the intermediate TTD report (in a temp file; path printed to stderr)")
    parser.add_argument("--json-output", help="write the TTD report to this path and keep it (for ttd-timeline.py)")

    parser.add_argument(
        "--summary",
        action="store_true",
        help="run BOTH the dynamic and static passes and print one unified capability "
        "report (dynamic + code capabilities merged, with ATT&CK/MBC roll-ups); "
        "capa-cpp passthrough args after `--` are ignored in this mode",
    )

    # Assembly (static) scanning of reconstructed executable regions.
    parser.add_argument(
        "--scan-code",
        action="store_true",
        help="additionally reconstruct executable regions and capa-static scan them",
    )
    parser.add_argument(
        "--code-only",
        action="store_true",
        help="do only the assembly (static) scan; skip the dynamic call report",
    )
    parser.add_argument("--max-code-scans", type=int, default=8, help="cap snapshots per region (0 = unlimited)")
    parser.add_argument("--scan-data", action="store_true", help="also reconstruct/scan non-executable regions")
    parser.add_argument(
        "--no-scan-modules",
        action="store_true",
        help="do not watch the sample's own module images, only the regions the discovery "
        "providers turn up. Module images are the expensive half of the scan: a program that "
        "writes across its own image yields a snapshot per generation, and the recording holds "
        "every instruction address it ever ran there",
    )
    parser.add_argument(
        "--max-region-bytes",
        help="skip regions larger than this (default 256 MiB; 0 = no limit). Decimal, or hex "
        "with an explicit 0x prefix",
    )
    parser.add_argument(
        "--max-write-log-bytes",
        help="ceiling on every tracked region's recording together (default 1 GiB; 0 = no "
        "limit). All regions are recorded in one replay, so the sum is what has to be bounded; "
        "on reaching it the largest recording is dropped and the pass continues",
    )
    parser.add_argument("--keep-dumps", action="store_true", help="keep the reconstructed .bin snapshots")
    parser.add_argument("--code-output", help="write static capability records here (for ttd-timeline.py --code)")
    parser.add_argument(
        "--code-hits-output",
        help="also replay the trace with execute watchpoints on the matched code sites and "
        "write the execution-hit records here (for ttd-timeline.py --code-hits)",
    )
    parser.add_argument(
        "--hit-gap",
        type=int,
        help="TTD Sequence gap that separates a code capability's executions into distinct "
        "visits in --code-hits-output (default 256; larger collapses more)",
    )
    parser.add_argument(
        "--hit-dedup",
        choices=["visit", "reentry"],
        help="grouping for --code-hits-output: 'visit' (default, per-capability cadence) or "
        "'reentry' (per-region execution bursts, coarser)",
    )
    parser.add_argument("--rebuild-index", action="store_true", help="delete an unloadable .idx and rebuild it")

    args, capa_extra = parser.parse_known_args(argv)
    # argparse leaves a leading "--" in capa_extra if present; drop it
    if capa_extra and capa_extra[0] == "--":
        capa_extra = capa_extra[1:]

    trace = Path(args.trace)
    if not trace.is_file():
        sys.exit(f"trace not found: {trace}")
    rules = Path(args.rules).resolve()
    if not rules.exists():
        sys.exit(f"rules path not found: {args.rules}")

    extractor = find_extractor(args.extractor)
    capa_cpp = find_capa_cpp(args.capa_cpp)

    if args.summary:
        return run_summary(args, extractor, capa_cpp, trace, rules)

    rc = 0
    if not args.code_only:
        rc = run_dynamic(args, extractor, capa_cpp, trace, rules, capa_extra)

    if args.scan_code or args.code_only:
        code_rc = run_code_scan(args, extractor, capa_cpp, trace, rules)
        rc = rc or code_rc

    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
