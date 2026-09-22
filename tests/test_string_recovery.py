#!/usr/bin/env python3
"""Regression test for string arguments the sweep's thread view cannot read.

Argument decoding happens inside a TTD call/return callback, whose IThreadView answers
memory queries at ThreadLocal fidelity only (IReplayEngine.h:1440). ThreadLocal sees what
the current thread touched near the current position, so a string argument sitting in a
heap buffer the caller filled earlier reads back as nothing and the report keeps only the
pointer. The bytes are in the trace throughout: a cursor parked at the same position and
asked at GloballyConservative returns them, which is what extract.cpp's recovery pass does.

This checks that the recovery actually happens, because the failure is silent. A regression
does not crash or error; it just quietly drops strings, and capa then never sees the String
features they carry.

The traces are too large to commit, so pass one in:

    python tests/test_string_recovery.py <trace.run> [--extractor <ttdcapa-extract.exe>]

Expectations are keyed by trace file name. A trace with none registered still runs the
generic checks, which apply to any trace.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# position -> (module, api, param name, exact decoded string)
#
# Every one of these was unreadable at its call position before the recovery pass, and each
# is the *first* use of that buffer in the trace: the beacon fills its config once, and until
# something reads it back the bytes are not thread-locally visible. Later check-ins resolved
# even without the fix, which is exactly why this went unnoticed.
EXPECTATIONS = {
    "beacon_x6401.run": [
        ("1104:DC9", "wininet", "InternetOpenA", "lpszAgent",
         "Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; DigExt; DTS Agent"),
        ("27BB:380", "wininet", "InternetConnectA", "lpszServerName", "192.168.81.129"),
        ("2DF1:173A", "wininet", "HttpOpenRequestA", "lpszVerb", "GET"),
    ],
}

STRING_KINDS = ("str", "wstr")


def extract(trace: Path, extractor: Path, out_path: Path) -> None:
    # --recover-strings explicitly: the seeking pass is opt-in, and the whole point of this
    # test is the recovery, so it has to be switched on. The free read at each call's return
    # runs either way and settles most of it; the flag adds the seeking pass on top.
    cmd = [str(extractor), str(trace), "--recover-strings", "-o", str(out_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(f"extractor failed ({proc.returncode}):\n{proc.stderr}")


def find_extractor(explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            sys.exit(f"extractor not found: {p}")
        return p
    p = ROOT / "ttd" / "bin" / "x64" / "Release" / "ttdcapa-extract.exe"
    if not p.is_file():
        sys.exit(f"extractor not found at {p}; build it or pass --extractor")
    return p


def check_expectations(calls: list, expectations: list) -> list[str]:
    """Each named parameter must decode to its exact string, in params and in args."""
    failures = []
    by_position = {c["position"]: c for c in calls}
    for position, module, api, param, expected in expectations:
        call = by_position.get(position)
        if call is None:
            failures.append(f"{position}: no call recorded at this position")
            continue
        if call.get("module") != module or call.get("api") != api:
            failures.append(
                f"{position}: expected {module}.{api}, found "
                f"{call.get('module')}.{call.get('api')}"
            )
            continue
        found = [p for p in call.get("params", []) if p.get("name") == param]
        if not found:
            failures.append(f"{position} {api}: no parameter named {param}")
            continue
        actual = found[0].get("str")
        if actual is None:
            failures.append(
                f"{position} {api}({param}): not decoded, still the bare pointer "
                f"{found[0].get('value'):#x}"
            )
        elif actual != expected:
            failures.append(f"{position} {api}({param}): {actual!r} != {expected!r}")
        elif expected not in call.get("args", []):
            # params is the reader's view; args is what capa matches on. A string that
            # reaches one but not the other is recovered evidence nothing can use.
            failures.append(f"{position} {api}({param}): decoded but missing from args")
    return failures


def check_invariants(calls: list) -> list[str]:
    """Checks that hold for any trace, whatever it recorded.

    These guard the two properties the recovery machinery can break silently.

    `args` is what capa matches rules against and `params` is the reader's view, and the
    recovery pass writes into `params` and then rebuilds `args` from it. Miss that rebuild
    for any of the paths that can recover a string -- the read at the call's return, the
    seeking pass, the [Out] pass -- and the string is recovered into a report nothing acts
    on, which is the same silent nothing as not recovering it. So every parameter's entry in
    `args` must agree with its entry in `params`.

    The second is the truncation rule toCapaArgs() enforces: a string known to have stopped
    before its terminator must stay out of `args`. The truncation is an artifact of what the
    trace recorded rather than a fact about the program, and a prefix satisfies rule
    alternations the whole value does not -- `api-ms-win-e` is a cut-off `api-ms-win-core-`
    name that matches things the real one never would.

    Deliberately not checked: text made of control bytes, as a proxy for zero-fill being
    recorded as data. readAnsiString and readWideString both return None on any byte below
    0x20 other than tab, CR and LF, so no such string can reach the report by construction
    and the check can only ever pass. It would not catch a zero-fill truncation either,
    since that produces clean text -- see ARGUMENT-DECODING.md on why nothing else can
    catch one either.
    """
    failures = []
    mismatched = truncated_in_args = 0
    for call in calls:
        params, args = call.get("params"), call.get("args", [])
        if not params or len(params) != len(args):
            continue  # heuristic capture: no params, or an arity we cannot line up
        for param, arg in zip(params, args):
            complete = "str" in param and param["str"] and not param.get("str_truncated")
            # toCapaArgs casts the raw value to int64_t; the report writes params["value"]
            # unsigned, so -1 there is 0xFFFFFFFFFFFFFFFF here. Same 64 bits either way.
            raw = param.get("value", 0)
            expected = param["str"] if complete else (
                raw - (1 << 64) if raw >= (1 << 63) else raw)
            if arg != expected:
                mismatched += 1
                if mismatched <= 3:
                    failures.append(
                        f"{call['position']} {call.get('api')}({param.get('name')}): "
                        f"args has {arg!r}, params says {expected!r}"
                    )
            if param.get("str_truncated") and arg == param.get("str"):
                truncated_in_args += 1
    if mismatched > 3:
        failures.append(f"...and {mismatched - 3} further args/params mismatch(es)")
    if truncated_in_args:
        failures.append(
            f"{truncated_in_args} truncated string(s) reached args, where capa would "
            f"match a prefix as though it were the whole value"
        )
    return failures


def summarise(calls: list) -> None:
    """How much of the string surface decoded, as context for whoever runs this."""
    resolved = unresolved = 0
    for call in calls:
        for param in call.get("params", []):
            if param.get("kind") not in STRING_KINDS or not param.get("value"):
                continue
            if "str" in param:
                resolved += 1
            else:
                unresolved += 1
    total = resolved + unresolved
    if total:
        print(f"string parameters: {resolved}/{total} decoded "
              f"({100.0 * resolved / total:.1f}%), {unresolved} left as pointers")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("trace", help="a TTD .run trace to extract and check")
    ap.add_argument("--extractor", help="path to ttdcapa-extract.exe")
    ap.add_argument("--keep-json", action="store_true", help="keep the extracted report")
    args = ap.parse_args(argv)

    trace = Path(args.trace)
    if not trace.is_file():
        sys.exit(f"trace not found: {trace}")
    extractor = find_extractor(args.extractor)

    with tempfile.TemporaryDirectory() as tmp:
        report_path = Path(tmp) / "report.ttd.json"
        print(f"extracting {trace.name} with {extractor.name} ...")
        extract(trace, extractor, report_path)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if args.keep_json:
            kept = Path.cwd() / f"{trace.stem}.ttd.json"
            kept.write_text(json.dumps(report), encoding="utf-8")
            print(f"kept report: {kept}")

    calls = report["processes"][0]["calls"]
    print(f"{len(calls)} call(s) recorded")
    summarise(calls)

    failures = check_invariants(calls)
    expectations = EXPECTATIONS.get(trace.name)
    if expectations is None:
        print(f"note: no per-call expectations registered for {trace.name}; "
              "ran the generic checks only")
    else:
        failures += check_expectations(calls, expectations)
        print(f"checked {len(expectations)} recovered string(s)")

    if failures:
        print("\nFAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
