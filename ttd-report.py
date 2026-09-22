"""
One consolidated capability report over a TTD trace: the *dynamic* (API-call) and
*static* (reconstructed-code) capabilities merged into a single, source-tagged view.

    python ttd-report.py <report.ttd.json> -r <rules-dir> [--code code-caps.json]

`<report.ttd.json>` is a report from ttdcapa-extract (or `ttd-capa.py --keep-json`);
`--code` is the static capability records `ttd-capa.py --code-output` /
`capa-cpp --scan-code-manifest -o` produced. Dynamic matching is done by capa-cpp (`-j`).

The report shows, in one place:
  * a summary line (how many capabilities came from each source),
  * an ATT&CK and an MBC roll-up,
  * a unified capability table tagged dyn / code / both with per-source match counts,
  * a static-code detail listing (region + offset + first TTD position) for triage.

This has no Python-capa dependency; it shells out to capa-cpp for the dynamic matching.
"""
import sys
import json
import argparse
from pathlib import Path
from typing import Optional

from ttd_common import find_capa_cpp, run_capa_cpp_json, position_key_from_pos

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


# --- merge ------------------------------------------------------------------------------


def fmt_attack(a: dict) -> str:
    parts = "::".join(p for p in (a.get("tactic"), a.get("technique"), a.get("subtechnique")) if p)
    tid = a.get("id")
    return f"{parts} [{tid}]" if tid else parts


def fmt_mbc(b: dict) -> str:
    parts = "::".join(p for p in (b.get("objective"), b.get("behavior"), b.get("method")) if p)
    bid = b.get("id")
    return f"{parts} [{bid}]" if bid else parts


def merge_capabilities(dyn_doc: dict, code_records: Optional[list]) -> dict:
    """Return {rule -> {namespace, dyn, code, code_locs, attack, mbc}} across both sources."""
    caps: dict[str, dict] = {}

    for rule, ent in dyn_doc.get("rules", {}).items():
        meta = ent.get("meta", {})
        if meta.get("is_subscope_rule"):
            continue
        ns = meta.get("namespace", "") or ""
        if ns.startswith("internal/") or meta.get("lib"):
            continue
        caps[rule] = {
            "namespace": ns,
            "dyn": len(ent.get("matches", [])),
            "code": 0,
            "code_locs": [],  # (position, base, offset)
            "attack": meta.get("attack", []),
            "mbc": meta.get("mbc", []),
        }

    for rec in code_records or []:
        rule = rec.get("rule", "")
        ns = rec.get("namespace", "") or ""
        c = caps.setdefault(
            rule,
            {"namespace": ns, "dyn": 0, "code": 0, "code_locs": [], "attack": [], "mbc": []},
        )
        if not c["namespace"]:
            c["namespace"] = ns
        c["code"] += rec.get("scans_matched", 1)
        c["code_locs"].append((rec.get("position", "") or "", rec.get("base", 0), rec.get("offset")))

    return caps


def source_tag(c: dict) -> str:
    if c["dyn"] and c["code"]:
        return "both"
    return "dyn" if c["dyn"] else "code"


# --- rendering --------------------------------------------------------------------------


def _table(headers: list[str], rows: list[list[str]], aligns: Optional[list[str]] = None) -> str:
    cols = len(headers)
    aligns = aligns or ["<"] * cols
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    out = []
    head = "  ".join(f"{headers[i]:{aligns[i]}{widths[i]}}" for i in range(cols))
    out.append(head)
    out.append("-" * len(head))
    for row in rows:
        out.append("  ".join(f"{row[i]:{aligns[i]}{widths[i]}}" for i in range(cols)))
    return "\n".join(out)


def render_report(dyn_doc: dict, code_records: Optional[list]) -> str:
    caps = merge_capabilities(dyn_doc, code_records)
    meta = dyn_doc.get("meta", {})
    sample = meta.get("sample", {})
    analysis = meta.get("analysis", {})

    dyn_n = sum(1 for c in caps.values() if c["dyn"])
    code_n = sum(1 for c in caps.values() if c["code"])
    both_n = sum(1 for c in caps.values() if c["dyn"] and c["code"])
    regions = sorted({loc[1] for c in caps.values() for loc in c["code_locs"]})

    out: list[str] = []
    out.append("=" * 78)
    out.append("ttd-capa unified capability report")
    out.append("=" * 78)
    if sample.get("sha256"):
        out.append(f"  sha256   {sample['sha256']}")
    if sample.get("path"):
        out.append(f"  input    {sample['path']}")
    osv = analysis.get("os", "?")
    fmt = analysis.get("format", "?")
    arch = analysis.get("arch", "?")
    out.append(f"  platform {osv} / {fmt} / {arch}")
    out.append("")
    out.append(
        f"  {len(caps)} unique capabilities: "
        f"{dyn_n} from API calls, {code_n} from reconstructed code "
        f"({len(regions)} region(s)), {both_n} seen by both."
    )
    out.append("")

    # ---- ATT&CK / MBC roll-ups (from the dynamic metadata) ----
    attack: dict[str, set[str]] = {}
    mbc: dict[str, set[str]] = {}
    for c in caps.values():
        for a in c["attack"]:
            tactic = a.get("tactic", "") or ""
            rest = fmt_attack(a)
            rest = rest.split("::", 1)[1] if "::" in rest else rest
            if tactic:
                attack.setdefault(tactic, set()).add(rest)
        for b in c["mbc"]:
            objective = b.get("objective", "") or ""
            rest = fmt_mbc(b)
            rest = rest.split("::", 1)[1] if "::" in rest else rest
            if objective:
                mbc.setdefault(objective, set()).add(rest)

    if attack:
        out.append("ATT&CK")
        rows = [[t.upper(), "\n".join(sorted(techs))] for t, techs in sorted(attack.items())]
        # flatten multi-line technique cells into repeated tactic rows for a simple table
        flat = []
        for tactic, techs in sorted(attack.items()):
            for i, tech in enumerate(sorted(techs)):
                flat.append([tactic.upper() if i == 0 else "", tech])
        out.append(_table(["Tactic", "Technique"], flat))
        out.append("")

    if mbc:
        out.append("MBC")
        flat = []
        for objective, behs in sorted(mbc.items()):
            for i, beh in enumerate(sorted(behs)):
                flat.append([objective.upper() if i == 0 else "", beh])
        out.append(_table(["Objective", "Behavior"], flat))
        out.append("")

    # ---- unified capability table ----
    out.append("CAPABILITIES  (src: dyn = API call, code = reconstructed code, both = seen by both)")
    rows = []
    for rule in sorted(caps, key=lambda r: (caps[r]["namespace"], r)):
        c = caps[rule]
        rows.append([
            rule,
            c["namespace"],
            source_tag(c),
            str(c["dyn"]) if c["dyn"] else "-",
            str(c["code"]) if c["code"] else "-",
        ])
    out.append(_table(
        ["Capability", "Namespace", "Src", "Dyn", "Code"],
        rows,
        aligns=["<", "<", "<", ">", ">"],
    ))
    out.append("")

    # ---- static-code detail: where each code capability sits, for triage / WinDbg ----
    code_caps = {r: c for r, c in caps.items() if c["code"]}
    if code_caps:
        out.append("STATIC CODE DETAIL  (region + offset + first TTD position)")
        rows = []
        for rule in sorted(code_caps, key=lambda r: code_caps[r]["namespace"]):
            c = code_caps[rule]
            # earliest position across this rule's regions
            loc = min(c["code_locs"], key=lambda l: position_key_from_pos(l[0]))
            pos, base, off = loc
            where = f"0x{base:x}" + (f"+0x{off:x}" if off is not None else "")
            rows.append([rule, c["namespace"], where, pos or "?"])
        out.append(_table(["Capability", "Namespace", "Region+Offset", "First TTD Pos"], rows))
        out.append("")

    return "\n".join(out)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Merge a TTD trace's dynamic (API) and static (code) capabilities into one report.",
    )
    parser.add_argument("report", help="path to a TTD report (.ttd.json) from ttdcapa-extract")
    parser.add_argument("-r", "--rules", required=True, help="capa rules directory")
    parser.add_argument("--code", help="static capability records (capa-cpp --scan-code-manifest -o)")
    parser.add_argument("--capa-cpp", help="path to capa-cpp.exe (default: auto-locate in capa-cpp/ or PATH)")
    parser.add_argument("-o", "--output", help="write the report here instead of stdout")
    args = parser.parse_args(argv)

    report_path = Path(args.report)
    if not report_path.is_file():
        sys.exit(f"report not found: {report_path}")
    rules_path = Path(args.rules)
    if not rules_path.exists():
        sys.exit(f"rules path not found: {rules_path}")

    code_records = None
    if args.code:
        code_path = Path(args.code)
        if not code_path.is_file():
            sys.exit(f"code capability file not found: {code_path}")
        code_records = json.loads(code_path.read_text(encoding="utf-8"))

    capa_cpp = find_capa_cpp(args.capa_cpp)
    dyn_doc = run_capa_cpp_json(capa_cpp, report_path, rules_path, log_prefix="ttd-report")

    report = render_report(dyn_doc, code_records)
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(f"[ttd-report] wrote report to {args.output}", file=sys.stderr)
    else:
        print(report)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
