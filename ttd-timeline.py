"""
Print a chronological "timeline" of what the TTD extractor uncovered, ordered by
TTD trace position so you can step through it in WinDbg.

Two modes:

  * capability timeline (default, needs a rules dir) -- runs capa-cpp over the report and
    lists every capability that fired at call / span-of-calls scope, in trace order, each
    tagged with its TTD position (Sequence:Steps) and thread id:

        python ttd-timeline.py report.ttd.json -r capa-rules/

  * call timeline (--calls, no rules needed) -- lists every resolved API call the
    extractor recorded, in trace order, with its TTD position, tid, args and retval:

        python ttd-timeline.py report.ttd.json --calls

The TTD position is exactly what WinDbg shows: paste "Sequence:Steps" into the
time-travel position box, or use `!tt <Sequence>:<Steps>`, to jump to the event.

The input can be a report .ttd.json, or a .run trace directly -- in which case the trace is
extracted (and, with --scan-code, code-scanned + hit-traced) on the fly, so one command goes
from trace to timeline:

    python ttd-timeline.py trace.run -r rules --scan-code

This tool has no Python-capa dependency: `--calls` reads the report JSON directly, and the
capability timeline shells out to capa-cpp (`-j`) and maps each match back to the report's
recorded calls for its TTD position.

Rows are plain tuples of (position key, position label, tid, namespace, capability, site),
so a host project can extend the same position-ordered table with rows from other analyses.
"""
import sys
import json
import shutil
import tempfile
import argparse
import subprocess
from pathlib import Path
from typing import Optional

from ttd_common import (
    find_capa_cpp,
    find_extractor,
    run_capa_cpp_json,
    position_key_from_pos,
)

# Recovered guest strings are arbitrary text -- non-Latin paths, HTTP bodies, the
# occasional lone surrogate from a half-written UTF-16 buffer. When stdout is a
# console Python uses UTF-8, but when it is redirected to a file it falls back to
# the locale encoding (cp1252 here), which cannot encode any of that and aborts the
# whole run. Pin UTF-8 and degrade unencodable characters instead of dying.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

_MASK = 0xFFFFFFFFFFFFFFFF


def build_from_trace(trace: Path, extractor: Path, rules_path: Optional[Path],
                     capa_cpp: Optional[Path], scan_code: bool, work: Path,
                     hit_gap: Optional[int] = None, hit_dedup: Optional[str] = None):
    """Extract a report from a .run trace (and, with scan_code, code capabilities + execution
    hits) into `work`. Returns (report_path, code_records, code_hits)."""
    report_path = work / "report.ttd.json"
    cmd = [str(extractor), str(trace), "-o", str(report_path)]
    print(f"[ttd-timeline] extracting report: {' '.join(cmd)}", file=sys.stderr)
    if subprocess.call(cmd) != 0 or not report_path.is_file() or report_path.stat().st_size == 0:
        sys.exit("ttdcapa-extract failed to produce a report")

    code_records = code_hits = None
    if scan_code:
        if rules_path is None:
            sys.exit("--scan-code needs -r <rules-dir> (capa-cpp matches the reconstructed code)")
        manifest = work / "manifest.json"
        code_caps = work / "code-caps.json"
        hits = work / "hits.json"

        scmd = [str(extractor), str(trace), "--scan-code",
                "--dump-dir", str(work), "--code-manifest", str(manifest)]
        print(f"[ttd-timeline] reconstructing code regions: {' '.join(scmd)}", file=sys.stderr)
        if subprocess.call(scmd) == 0 and manifest.is_file():
            capscan = [str(capa_cpp), "--scan-code-manifest", str(manifest),
                       "-r", str(rules_path), "--dumps-dir", str(work),
                       "-o", str(code_caps), "--quiet"]
            print(f"[ttd-timeline] static scan: {' '.join(capscan)}", file=sys.stderr)
            subprocess.call(capscan, stdout=subprocess.DEVNULL)
            if code_caps.is_file():
                code_records = json.loads(code_caps.read_text(encoding="utf-8"))
                hcmd = [str(extractor), str(trace),
                        "--trace-code-hits", str(code_caps), "--hits-output", str(hits)]
                if hit_gap is not None:
                    hcmd += ["--hit-gap", str(hit_gap)]
                if hit_dedup:
                    hcmd += ["--hit-dedup", hit_dedup]
                print(f"[ttd-timeline] tracing code execution hits: {' '.join(hcmd)}", file=sys.stderr)
                subprocess.call(hcmd)
                if hits.is_file():
                    code_hits = json.loads(hits.read_text(encoding="utf-8"))
        else:
            print("[ttd-timeline] no reconstructable code regions; report-only timeline", file=sys.stderr)

    return report_path, code_records, code_hits


# --- report parsing (pure JSON; no capa) -----------------------------------------------


def position_key(call: dict) -> tuple[int, int]:
    """Sort key for a call, falling back to the synthetic `seq` counter."""
    pos = call.get("position") or ""
    if pos and ":" in pos:
        seq, _, steps = pos.partition(":")
        try:
            return (int(seq, 16), int(steps, 16))
        except ValueError:
            pass
    return (call.get("seq", 0), 0)


def position_label(call: dict) -> str:
    pos = call.get("position") or ""
    return pos if pos else f"seq={call.get('seq', 0)}"


def fmt_arg(a) -> str:
    """Integers as hex (pointers/handles read naturally); strings quoted."""
    if isinstance(a, bool):
        return repr(a)
    if isinstance(a, int):
        # show negatives as their 64-bit two's-complement form, e.g. -2 -> 0xff..fe
        return f"0x{a & _MASK:x}" if a < 0 else f"0x{a:x}"
    return repr(a)


def fmt_param(p: dict) -> str:
    """One metadata-decoded parameter as `name=value`.

    Prefers the most informative rendering the extractor managed: decoded text, then
    symbolic flag names, then a dereferenced pointee, then the raw value.
    """
    if p.get("str") is not None:
        value = repr(p["str"])
    elif p.get("flags"):
        value = "|".join(p["flags"])
    elif p.get("float") is not None:
        value = repr(p["float"])
    else:
        value = fmt_arg(p.get("value"))
        if p.get("deref") is not None:
            value += f"->{fmt_arg(p['deref'])}"
    if p.get("at_return"):
        value += "@ret"
    name = p.get("name")
    return f"{name}={value}" if name else value


def format_call(call: dict) -> str:
    module = call.get("module") or ""
    api = f"{module}.{call.get('api', '')}" if module else call.get("api", "")
    params = call.get("params")
    if params:
        args = ", ".join(fmt_param(p) for p in params)
    else:
        args = ", ".join(fmt_arg(a) for a in call.get("args", []))
    ret = call.get("ret")
    ret_s = "" if ret is None else f" -> 0x{ret & _MASK:x}"
    return f"{api}({args}){ret_s}"


def build_call_index(report: dict):
    """Return (all_calls, lookup).

    all_calls: list of (ppid, pid, tid, call) for every recorded call.
    lookup:    dict[(ppid, pid, tid)] -> calls sorted by seq. The list index matches
               capa-cpp's dynamic call address id (it groups a thread's calls in report
               order, then stable-sorts by seq), so a capa-cpp call address
               [ppid, pid, tid, id] resolves to lookup[(ppid,pid,tid)][id].
    """
    all_calls = []
    lookup: dict[tuple[int, int, int], list[dict]] = {}
    for proc in report.get("processes", []):
        ppid = proc.get("ppid", 0)
        pid = proc.get("pid", 0)
        by_tid: dict[int, list[dict]] = {}
        for call in proc.get("calls", []):
            by_tid.setdefault(call.get("tid", 0), []).append(call)
        for tid, calls in by_tid.items():
            calls_sorted = sorted(calls, key=lambda c: c.get("seq", 0))  # stable
            lookup[(ppid, pid, tid)] = calls_sorted
            for c in calls_sorted:
                all_calls.append((ppid, pid, tid, c))
    return all_calls, lookup


# --- call timeline ---------------------------------------------------------------------


def render_call_timeline(report: dict, limit: Optional[int]) -> int:
    all_calls, _ = build_call_index(report)
    events = [
        (position_key(call), pid, tid, call) for _, pid, tid, call in all_calls
    ]
    events.sort(key=lambda e: e[0])
    if limit:
        events = events[:limit]

    if not events:
        print("no calls recorded.")
        return 0

    posw = max((len(position_label(c)) for _, _, _, c in events), default=8)
    print(f"{'TTD POS':<{posw}}  {'PID':>6}  {'TID':>6}  CALL")
    print("-" * (posw + 2 + 6 + 2 + 6 + 2 + 4))
    for _, pid, tid, call in events:
        print(f"{position_label(call):<{posw}}  {pid:>6}  {tid:>6}  {format_call(call)}")
    sys.stdout.flush()
    print(f"\n{len(events)} calls.", file=sys.stderr)
    return 0


# --- static (assembly) capability records ----------------------------------------------


def load_code_records(code_path: Path) -> list[dict]:
    """Load the capability records capa-cpp's static scan (`-o`) produced (may be empty)."""
    if not code_path.is_file():
        sys.exit(f"code capability file not found: {code_path}")
    return json.loads(code_path.read_text(encoding="utf-8"))


def code_rows(code_records: list[dict]) -> list[tuple]:
    """Turn static (assembly) capability records into capability-timeline tuples.

    Shaped exactly like the dynamic rows so both interleave in one position-ordered table.
    The 'triggering' column points at the reconstructed region and match offset instead of
    an API call, since these fired on disassembled code rather than a call. The position is
    the region's *reconstruction* position (when code first ran there), not necessarily when
    this particular capability executed - pass --code-hits for real per-capability positions.
    """
    rows = []
    for rec in code_records:
        pos = rec.get("position", "") or ""
        base = rec.get("base", 0)
        offset = rec.get("offset")
        where = f"code@0x{base:x}" + (f"+0x{offset:x}" if offset is not None else "")
        rows.append(
            (
                position_key_from_pos(pos),
                pos.upper() if pos else "?",  # match the dynamic (report) positions' casing
                "-",  # no single thread attributed to a reconstructed region
                rec.get("namespace", "") or "",
                rec.get("rule", ""),
                where,
            )
        )
    return rows


def load_code_hits(path: Path) -> list[dict]:
    """Load the execute-hit records ttdcapa-extract --trace-code-hits produced."""
    if not path.is_file():
        sys.exit(f"code-hits file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def build_va_rule_map(code_records: list[dict]) -> dict[int, list[tuple[str, str]]]:
    """Map each matched instruction VA -> list of (rule, namespace) from the static records.

    Several capabilities can match at the *same* VA -- most commonly function-scope rules,
    which all locate at the function's entry address -- so every rule at a VA is kept, not
    just the last one loaded.
    """
    m: dict[int, list[tuple[str, str]]] = {}
    for rec in code_records or []:
        ns = rec.get("namespace", "") or ""
        rule = rec.get("rule", "")
        for va in rec.get("vas", []):
            m.setdefault(va, []).append((rule, ns))
    return m


def code_hit_rows(code_hits: list[dict], va_rule: dict[int, list[tuple[str, str]]]) -> list[tuple]:
    """Turn execute-hit records into capability-timeline tuples at *real* execution positions.

    One row per (capability, matched code site) at the first TTD position it ran. Loop spam is
    already collapsed by the tracer (visit-coalescing dedup); the hit count is shown as `(Nx)`.
    """
    rows = []
    for h in code_hits:
        va = h.get("va")
        pairs = va_rule.get(va)
        if not pairs:
            continue  # a VA with no capability mapping (shouldn't happen)
        pos = h.get("position", "") or ""
        hits = h.get("hits", 0)
        where = f"code@0x{va:x}" + (f" ({hits}x)" if hits and hits > 1 else "")
        poskey = position_key_from_pos(pos)
        posdisp = pos.upper() if pos else "?"
        tid = h.get("tid", "-")
        for rule, ns in pairs:
            rows.append((poskey, posdisp, tid, ns, rule, where))
    return rows


def static_rows(code_records: Optional[list[dict]], code_hits: Optional[list[dict]]) -> list[tuple]:
    """Rows for static (code) capabilities: execution-positioned if hits are available,
    otherwise the region-reconstruction position."""
    if code_hits is not None:
        rows = code_hit_rows(code_hits, build_va_rule_map(code_records or []))
        # Any capability that produced no execution hit would otherwise vanish when
        # --code-hits is used: data/string matches (no executable site) and, defensively, an
        # instruction match whose VA never fired during replay. Surface those at their region
        # reconstruction position instead of dropping them.
        if code_records:
            hit_rules = {r[4] for r in rows}
            missing = [rec for rec in code_records if rec.get("rule") not in hit_rules]
            rows += code_rows(missing)
        return rows
    return code_rows(code_records or [])


def _print_capability_table(timeline: list[tuple], unpositioned: dict[str, str]) -> None:
    if timeline:
        # Size every column to its widest cell (including the header label). Python's `<w`
        # format pads but never truncates, so a value wider than the column would otherwise
        # push the following columns out of alignment.
        posw = max(len("TTD POS"), max(len(e[1]) for e in timeline))
        tidw = max(len("TID"), max(len(str(e[2])) for e in timeline))
        rulew = max(len("CAPABILITY"), max(len(e[4]) for e in timeline))
        nsw = max(len("NAMESPACE"), max(len(e[3]) for e in timeline))
        header = f"{'TTD POS':<{posw}}  {'TID':>{tidw}}  {'CAPABILITY':<{rulew}}  {'NAMESPACE':<{nsw}}  TRIGGERING CALL"
        print(header)
        print("-" * len(header))
        for _, pos, tid, namespace, rule_name, call_name in timeline:
            print(f"{pos:<{posw}}  {str(tid):>{tidw}}  {rule_name:<{rulew}}  {namespace:<{nsw}}  {call_name}")

    if unpositioned:
        print("\n# capabilities matched at process/thread/file scope (no single TTD position):")
        for rule_name, namespace in sorted(unpositioned.items()):
            print(f"  {rule_name}  [{namespace}]")


def render_code_timeline(code_records: Optional[list[dict]], code_hits: Optional[list[dict]],
                         limit: Optional[int]) -> int:
    timeline = static_rows(code_records, code_hits)
    timeline.sort(key=lambda e: e[0])
    if limit:
        timeline = timeline[:limit]
    _print_capability_table(timeline, {})
    sys.stdout.flush()
    positioned = "execution-positioned" if code_hits is not None else "region-positioned"
    print(f"\n{len(timeline)} static (assembly) capability matches ({positioned}).", file=sys.stderr)
    return 0


# --- capability timeline (capa-cpp -j) -------------------------------------------------


def render_capability_timeline(
    report: dict,
    capa_cpp: Path,
    report_path: Path,
    rules_path: Path,
    limit: Optional[int],
    code_records: Optional[list[dict]] = None,
    code_hits: Optional[list[dict]] = None,
) -> int:
    _, lookup = build_call_index(report)
    doc = run_capa_cpp_json(capa_cpp, report_path, rules_path, log_prefix="ttd-timeline")

    timeline = []  # (poskey, pos_label, tid, namespace, rule, call_name)
    unpositioned: dict[str, str] = {}  # rule -> namespace, for process/thread/file scope

    for rule_name, entry in doc.get("rules", {}).items():
        meta = entry.get("meta", {})
        if meta.get("is_subscope_rule"):
            # synthetic helper rules, not user-facing capabilities
            continue
        namespace = meta.get("namespace", "") or ""
        if namespace.startswith("internal/") or meta.get("lib"):
            # capa uses these internally; they aren't user-facing capabilities
            continue

        for addr, _tree in entry.get("matches", []):
            if addr.get("type") == "call":
                ppid, pid, tid, cid = addr["value"]
                calls = lookup.get((ppid, pid, tid))
                if not calls or cid >= len(calls):
                    continue
                call = calls[cid]
                timeline.append(
                    (
                        position_key(call),
                        position_label(call),
                        tid,
                        namespace,
                        rule_name,
                        format_call(call),
                    )
                )
            else:
                # process / thread / file scope: no single navigable position
                unpositioned[rule_name] = namespace

    # Fold in static (assembly) capabilities so code and API capabilities share one timeline
    code_count = 0
    if code_records or code_hits:
        rows = static_rows(code_records, code_hits)
        code_count = len(rows)
        timeline.extend(rows)

    timeline.sort(key=lambda e: e[0])
    if limit:
        timeline = timeline[:limit]

    _print_capability_table(timeline, unpositioned)

    sys.stdout.flush()
    print(
        f"\n{len(timeline)} positioned capability matches "
        f"({code_count} from reconstructed code); "
        f"{len(unpositioned)} scope-level capabilities.",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Print a TTD-position-ordered timeline of capabilities (or raw API calls) "
        "uncovered in a TTD report.",
    )
    parser.add_argument("report", nargs="?",
                        help="a TTD report (.ttd.json) from ttdcapa-extract, OR a .run trace to "
                        "extract and time-line in one step")
    parser.add_argument("-r", "--rules", help="capa rules directory (enables the capability timeline)")
    parser.add_argument("--capa-cpp", help="path to capa-cpp.exe (default: auto-locate in capa-cpp/ or PATH)")
    parser.add_argument("--extractor", help="path to ttdcapa-extract.exe (only used when the input is a .run trace)")
    parser.add_argument(
        "--scan-code",
        action="store_true",
        help="when given a .run trace, also reconstruct executable regions and fold code "
        "capabilities (at their real execution positions) into the timeline",
    )
    parser.add_argument(
        "--keep",
        action="store_true",
        help="keep the intermediate artifacts extracted from a .run trace (path printed to stderr)",
    )
    parser.add_argument(
        "--hit-gap",
        type=int,
        help="TTD Sequence gap that separates a code capability's executions into distinct "
        "timeline visits (only with --scan-code; default 256; larger collapses more)",
    )
    parser.add_argument(
        "--hit-dedup",
        choices=["visit", "reentry"],
        help="how code executions are grouped into timeline rows (only with --scan-code): "
        "'visit' (default) splits each capability by its own execution gaps (shows per-capability "
        "cadence); 'reentry' splits by the whole region's execution bursts (coarser)",
    )
    parser.add_argument(
        "--calls",
        action="store_true",
        help="list every recorded API call instead of capa capabilities (no rules needed)",
    )
    parser.add_argument(
        "--code",
        help="static (assembly) capability records from capa-cpp --scan-code-manifest -o; "
        "folded into the capability timeline, or shown alone if no report/--rules is given",
    )
    parser.add_argument(
        "--code-hits",
        help="execute-hit records from ttdcapa-extract --trace-code-hits; positions each code "
        "capability at the moment it actually ran (requires --code for the VA->rule mapping)",
    )
    parser.add_argument("--limit", type=int, help="show only the first N timeline rows")
    args = parser.parse_args(argv)

    code_records = load_code_records(Path(args.code)) if args.code else None
    code_hits = load_code_hits(Path(args.code_hits)) if args.code_hits else None
    if code_hits is not None and code_records is None:
        sys.exit("--code-hits needs --code (the records map matched VAs back to capabilities)")

    # Static-only mode: a code timeline with no dynamic report at all.
    if not args.report:
        if code_records is None and code_hits is None:
            sys.exit("nothing to show: pass a report, a .run trace, or --code <records.json>")
        return render_code_timeline(code_records, code_hits, args.limit)

    work: Optional[Path] = None
    try:
        # A .run trace is extracted (and optionally code-scanned) on the fly; a .json is a
        # report used directly.
        if args.report.lower().endswith(".run"):
            trace = Path(args.report)
            if not trace.is_file():
                sys.exit(f"trace not found: {trace}")
            extractor = find_extractor(args.extractor)
            rules_path = Path(args.rules) if args.rules else None
            capa_cpp = find_capa_cpp(args.capa_cpp) if args.scan_code else None
            work = Path(tempfile.mkdtemp(prefix="ttd-timeline-"))
            report_path, gen_records, gen_hits = build_from_trace(
                trace, extractor, rules_path, capa_cpp, args.scan_code, work,
                args.hit_gap, args.hit_dedup
            )
            # explicit --code/--code-hits win over generated ones
            if code_records is None:
                code_records = gen_records
            if code_hits is None:
                code_hits = gen_hits
            if args.keep:
                print(f"[ttd-timeline] kept intermediate artifacts in: {work}", file=sys.stderr)
        else:
            report_path = Path(args.report)
            if not report_path.is_file():
                sys.exit(f"report not found: {report_path}")

        report = json.loads(report_path.read_text(encoding="utf-8"))

        if args.calls or not args.rules:
            if not args.calls and not args.rules:
                print(
                    "[ttd-timeline] no --rules given; showing the API-call timeline. "
                    "pass -r <rules-dir> for a capability timeline.",
                    file=sys.stderr,
                )
            rc = render_call_timeline(report, args.limit)
            if code_records or code_hits:
                print("\n# static (assembly) capability timeline:")
                render_code_timeline(code_records, code_hits, args.limit)
            return rc

        rules_path = Path(args.rules)
        if not rules_path.exists():
            sys.exit(f"rules path not found: {rules_path}")
        capa_cpp = find_capa_cpp(args.capa_cpp)
        return render_capability_timeline(
            report, capa_cpp, report_path, rules_path, args.limit,
            code_records, code_hits
        )
    finally:
        if work and not args.keep:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
