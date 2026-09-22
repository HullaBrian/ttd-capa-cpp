# Design: code-scan capabilities in the timeline (execute-positioned)

## The problem

Dynamic (API-call) capabilities already land in `ttd-timeline.py` at their exact TTD
position - the position of the call that triggered them. Static (code-scan) capabilities
do **not**: today each one is tagged with a single position, the *generation snapshot*
position at which its region was reconstructed (`first seen 366:19`). So in the timeline a
code capability shows up once, at the moment the region was first written/executed - not at
the moments the matched code *actually ran*.

We want code capabilities placed in the timeline at their **real execution positions**, and
we want loop/repeat spam collapsed so a routine that runs 10,000 times doesn't produce
10,000 rows.

## What we have to work with

- The static scan (capa-cpp `--scan-code-manifest`) knows, per matched rule per region, the
  **match offset** → virtual address `VA = region.base + offset`. Today it records one
  representative offset (the earliest) per rule per region.
- `ttdcapa-extract --scan-code` already sets **execute memory watchpoints** while replaying
  (that's how it detects "writes-then-execute" generations). The machinery to watch an
  address for execution and read the TTD position on each hit already exists in the
  extractor.
- Every hit can be stamped with the navigable TTD position (`Sequence:Steps`) and tid - the
  same position the call timeline already uses.

## Proposed approach (two extra passes, extractor-driven)

### 1. capa-cpp: emit *all* match VAs per code capability
Extend the static `-o` record so each rule carries the set of instruction addresses it
matched at, not just the earliest offset:

```json
{ "rule": "encrypt data using AES", "namespace": "...", "base": 17891328,
  "vas": [ 17936742, 17972010 ], "kind": "insn", ... }
```

`kind` distinguishes an **instruction** match (has a real execution site) from a
**data/file** match (a string/byte reference with no executed instruction - e.g. "reference
Base64 string"). Only `insn` matches can be execution-positioned; data matches stay at the
region generation position (or are listed separately).

### 2. ttdcapa-extract: an execute-hit pass
A new mode (`--trace-code-hits <vas.json>` or folded into `--scan-code`) that:
- takes the union of matched VAs,
- replays the trace once, setting an execute watchpoint on each VA (dozens of addresses →
  modest; batch them into a single replay),
- on each hit records `(va, position, tid)`,
- applies **dedup** (below),
- emits `{ va, hits: [ { position, tid, count } ] }`.

### 3. Dedup looped results
A tight loop hits the same VA in a burst of near-consecutive positions. Options, cheapest
first:

- **First-only (v1):** per VA, keep the first execution position and a total hit count →
  one timeline row: *"capability X first executed at P (n times)"*. No loop spam, and the
  position is exactly what you paste into WinDbg. This is the recommended first cut.
- **Visit-coalescing (v2):** emit a new event only when the gap since the last hit at that
  VA exceeds a threshold in sequence units, i.e. control left and re-entered. Captures
  *distinct invocations* (a beacon that AES-encrypts each check-in shows one row per
  check-in) without the per-iteration spam.
- **Re-entry detection (v3):** emit only when the previously executed instruction was
  outside the matched function/region. Most precise, needs the prior-instruction context.

Always `log()` when a VA's events are truncated by a cap, so silent loss never reads as
"only ran once".

## Data flow

```
ttdcapa-extract --scan-code ─► manifest + .bin dumps
capa-cpp --scan-code-manifest ─► records with per-rule VAs (kind=insn|data)
        │  (collect the insn VAs)
        ▼
ttdcapa-extract --trace-code-hits vas.json ─► dedup'd (va → [positions]) 
        ▼
ttd-timeline.py ─► map va→rule (from records), drop rows into the position-ordered timeline
```

`ttd-timeline.py`'s capability timeline already interleaves dynamic and static rows; the
only change is that a code capability's rows now come from real execution positions instead
of the single generation position. `ttd-report.py`'s static-code detail can likewise show
*"first executed 3F2:1A0, 47x"* instead of the reconstruction position.

## Open questions / risks

- **Watchpoint cost.** Execute watchpoints on many addresses across a full replay can be
  slow; measure on the beacon (matched VA count is small, so likely fine). One replay for
  all VAs, not one per VA.
- **VA ↔ instruction alignment.** A match offset must fall on an instruction boundary for
  the watchpoint to fire; capa-cpp already decodes instructions, so it can emit the aligned
  instruction VA rather than a raw operand offset.
- **Data-scope matches** (strings, byte constants) have no execution site - keep them at the
  region position and label them as such, don't force a fake position.
- **Relocation.** VAs are absolute guest addresses from the reconstructed region, which is
  exactly the address space the replay watches - no translation needed (unlike the
  base-relative disassembly workspace).

## Milestones

- **M1 ✅ done** capa-cpp: per-rule `vas` + `kind` in the static `-o` record.
  (`capa-cpp/src/static/{capabilities,manifest}.*`, `main.cpp`.)
- **M2 ✅ done** ttdcapa-extract: execute-hit pass with first-only dedup (v1).
  New `--trace-code-hits <records.json> --hits-output <hits.json>` mode
  (`ttd/src/codescan/CodeHits.*`), emitting `[{va, position, tid, hits}]`.
- **M3 ✅ done** ttd-timeline: `--code-hits` positions code capabilities at their real
  execution position with `(Nx)` counts; `ttd-capa.py --code-hits-output` orchestrates the
  whole flow. Validated on the beacon: XOR 502×, RC4 184× collapse to one row each, and the
  matched sites spread across the timeline in execution order.
- **M4 v2 ✅ done** visit-coalescing dedup — `CodeHits.cpp` now accumulates one *visit* per
  VA per continuous run: consecutive hits within `--hit-gap` Sequence units (default 256)
  extend the current visit, a larger gap opens a new one. Each visit is emitted as its own
  `{va, position, tid, hits}` record, so the timeline (unchanged) shows a capability at each
  distinct invocation. Validated on the beacon: the XOR 502× loop stays one visit, while
  Base64/HTTP-status/RC4/AES resolve into their per-check-in invocations (revealing the C2
  cadence). Exposed through `ttd-capa.py`/`ttd-timeline.py --hit-gap`.
- **M4 v3 ✅ done (region-aligned re-entry)** `--hit-dedup reentry` splits a capability's
  executions by gaps in the *whole region's* execution rather than the VA's own, so all
  capabilities in one continuous burst of the reconstructed region share an invocation
  boundary. Region grouping comes from the records' `base` (no extra watchpoints). Note the
  semantic difference observed on the beacon: because its C2 region stays continuously
  active, `reentry` collapses Base64's four calls into one `(4x)` row, whereas the default
  `visit` mode shows them as four rows (the per-check-in cadence). So `visit` answers "how
  often did this capability fire" and `reentry` answers "how many separate bursts did this
  region run" -- both kept, `visit` is the default.
- **M4 data-scope ✅ done (lightweight)** `data`-kind matches (strings/bytes with no
  executable site) are no longer dropped from the execution timeline -- they're surfaced at
  their region reconstruction position (tid `-`). A heavier version could read-watchpoint the
  string address to time the actual reference; deferred as lower value.

### Not yet wired
- `ttd-report.py`'s static-code detail still shows the region reconstruction position; it
  could show the first execution position + hit count when a hits file is available.
