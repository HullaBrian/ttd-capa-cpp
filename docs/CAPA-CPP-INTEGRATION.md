# Integrating capa-cpp into ttd-capa

This document records the plan to move `ttd-capa` off **Python capa** and onto
**capa-cpp**, the C++ reimplementation of capa (at `../capa-cpp`), including full
coverage of the static "code scan" path so the Python-capa dependency can be removed
entirely.

## Background

`ttd-capa` uses the native `ttdcapa-extract.exe` to turn a TTD `.run` trace into a
neutral **TTD report JSON**, then feeds that JSON to Python capa (the HullaBrian/capa
fork vendored as the `capa/` git submodule) for rule matching. capa-cpp already replaces
the **dynamic** matching path 1:1 — verified at ~7.6 s vs ~44 s on the 91,455-call beacon
trace, with an identical capability table.

The native extractor is already C++ and is **shared unchanged** — only the *matcher* is
being swapped.

## Where Python capa is used today

| Consumer | What it calls | capa-cpp status |
|---|---|---|
| `ttd-capa.py` → `run_dynamic` | `python -m capa.main -f ttd -r rules report.json` | ✅ Drop-in today |
| `ttd-capa.py --scan-code` → `capa-cpp --scan-code-manifest` | capa **static vivisect/sc64** backend | ✅ Shipped (`src/static/`, section A below) |
| `ttd-timeline.py` | capa Python API: `TtdExtractor` + `find_capabilities` + per-call `TtdCall`/`params` | ⚠️ Partial (needs position/params in output) |

## What capa-cpp already has

The C++ engine was written scope-generic; the static machinery is present but unwired:

- **Scopes** `FUNCTION`/`BASIC_BLOCK`/`INSTRUCTION` are defined (`engine.h`), and
  `meta.scopes.static` plus static subscopes (`function:`/`basic block:`/`instruction:`)
  are already parsed and lowered (`rules.cpp`).
- **Every static feature type** already exists, parses, matches, and renders —
  `Mnemonic, Offset, OperandNumber, OperandOffset, Bytes, BasicBlock, Characteristic`.
  Characteristic strings match by raw equality (no allow-list), so the extractor just has
  to emit the right strings.
- **The matcher core is scope-agnostic** (`RuleSet::match` → `match_indexed`); the
  selectivity scorer already scores static features.
- **`AddressType::ABSOLUTE`** carries a VA and sorts/serializes correctly.

The only rule-engine gap is that `build_scope_index` iterates just the 5 dynamic+file
scopes (`rules.cpp:805`). Everything else missing lives in the **extractor** and the
**driver/CLI/render glue**.

## What capa-cpp needs — extractor spec

### A. Static analysis backend (bulk of the work)

Consumes the `--scan-code` **manifest + `.bin` dumps** and matches capa's static rules.

Manifest/dump facts (from `ttd/src/codescan/CodeScan.cpp`):

- Manifest: `{version, trace, arch:"x64", modules:[...], regions:[...]}`. Each region:
  `{base, size, classification:"exec"|"data", entries:[VA...], executed:[VA...],
  dumps:[{file, position, entry}]}`.
- `modules` is every module the trace loaded:
  `{name, path, base, size, arch, exports:[[rva, name], ...]}`. Exports are **RVAs**
  (the consumer adds the module's own `base`). Optional: a manifest written before this
  existed simply has no `modules` and scans exactly as it did before, minus `api:`.
- Each `.bin` is a **flat image of `[base, base+size)`** — file offset N == virtual
  address `base+N`. Unwritten bytes are `0x00`.
- `entries` = generation-start RIPs (**function-entry seeds**); `executed` = every
  executed instruction VA (**mid-function code seeds**), capped/subsampled at 131072.
  Both absolute VAs; may be **empty** for data/never-executed regions.
- **No import table** in a reconstructed region — but API names *are* resolvable via the
  manifest's `modules` export map; see the API-resolution note below.

New components required in capa-cpp:

1. **x86-64 disassembler** — recommend **Zydis** (vcpkg, MIT, decode-only, fast);
   Capstone is the fallback.
2. **Seeded code/CFG recovery** (`src/static/coderec.*`) — the key simplification that
   avoids reimplementing vivisect: seed decode from the manifest's `entries`/`executed`
   VAs rather than doing heuristic function discovery. Split basic blocks at
   branches/branch-targets, build per-function CFG + xref maps. Fall back to a blind
   linear sweep when `executed` is empty (mirrors `ttd_static_scan.py`).
3. **Static feature extractor** (`src/static/extractor.*`) emitting capa's exact static
   features:
   - **GLOBAL** (every scope): `Format`, `OS`, `Arch` (forced windows+amd64 for a blob).
   - **FILE**: `String` (ASCII+UTF-16LE), `Characteristic("embedded pe")` (XOR-MZ carve).
     `Import`/`Export`/`Section`/`FunctionName` are N/A for reconstructed regions.
   - **FUNCTION**: `Characteristic("loop")` (CFG SCC ≥2), `Characteristic("calls to")`.
   - **BASIC BLOCK**: `BasicBlock()` marker, `Characteristic("tight loop")`,
     `Characteristic("stack string")` (≥8 printable imm bytes mov'd to `[rbp/rsp]`).
   - **INSTRUCTION**: `Mnemonic`, `Number`/`OperandNumber`, `Offset`/`OperandOffset`,
     `Bytes` (operand derefs), `String` (operand ≥4 chars), and characteristics:
     `nzxor` (xor distinct operands, minus security-cookie), `call $+5`,
     `peb access` (`fs:[0x30]`/`gs:[0x60]`), `fs access`, `gs access`,
     `indirect call`, `cross section flow`, `calls from`, `recursive call`.
   - **API resolution — shipped.** The original plan deferred this: a reconstructed
     region has no import table, so `API(name)` looked unobtainable (Python capa hits the
     same wall on these dumps). The manifest's `modules` export map removes the wall.
     Shellcode that resolved its imports with `GetProcAddress` holds a table of bare
     addresses pointing *outside* the region; only the trace knows what lives there, so
     the recorder writes the process-wide export map into the manifest and
     `stat::build_symbol_map` turns those addresses back into `api:` features. This is
     what lets the ~500 `api:`-based rules fire on unpacked/injected code at all.

   Reuse capa's constants exactly: `MAX_STRUCTURE_SIZE=0x10000`,
   `MAX_BYTES_FEATURE_SIZE=0x100`, `MIN_STACKSTRING_LEN=8`, security-cookie delta `0x40`,
   thunk depth 5.
4. **Static capabilities driver** (`src/static/capabilities.*`) — a
   function→basic-block→instruction walker analogous to `capabilities.cpp`, using the
   existing `RuleSet::match(Scope::FUNCTION/BASIC_BLOCK/INSTRUCTION/FILE, …)`. Add the 3
   static scopes to `build_scope_index` (`rules.cpp:805`).
5. **CLI input mode**:
   `capa-cpp --scan-code-manifest <manifest.json> [--dumps-dir <dir>] -r <rules>`
   iterating regions/dumps, plus a JSON emitter matching the capability-record schema
   `ttd_static_scan.py -o` produces today (`{rule, namespace, position, base,
   classification, offset, scans_matched}`) so `ttd-timeline.py --code` keeps working.
6. **Render** — parameterize the dynamic-hardcoded bits: `meta.flavor`,
   `analysis.extractor`, the `"dynamic"` label, and a static `layout`/`feature_counts`
   variant (functions-based instead of process/thread/call).

### B. Timeline support (`ttd-timeline.py`)

- **`--calls` mode** needs no capa at all — the report already carries decoded `params`.
  Decouple it: parse the report JSON directly in pure Python.
- **Capability timeline mode** needs each match's **TTD position** + tid + triggering
  call. Add `position` (and optionally rendered api/params) to capa-cpp's `-j` per-match
  call locations (`position` is already parsed and retained in the C++ model). Then point
  the capability timeline at `capa-cpp -j`.

### C. Parity odds and ends (optional)

- **`com/` features** (COM GUID DB) — ~2 rules skipped today.
- **JSON match trees** — splice `match:` refs inline / use capa UUIDs for auto subscope
  rules (only matters for capa-Explorer-style consumers).

## ttd-capa side changes

- **`ttd-capa.py`**: add a `find_capa_cpp()` locator (mirrors `find_extractor()`);
  `run_dynamic` calls `capa-cpp report.json -r rules [extra]` instead of
  `python -m capa.main`; `run_code_scan` calls `capa-cpp --scan-code-manifest …` once the
  static backend lands. A `--python-capa` escape-hatch flag routes back to the Python
  matcher during transition.
- **`ttd_static_scan.py`**: retire once the static backend is validated (kept behind
  `--python-capa`).
- **`ttd-timeline.py`**: rework `--calls` to pure-report parsing; point the capability
  timeline at `capa-cpp -j`.
- Drop the `capa/` submodule + the `.venv` capa install once all three consumers are off
  Python.

## Phasing

1. **Dynamic cutover** (no capa-cpp changes): wire `run_dynamic` to `capa-cpp.exe`, add
   `--python-capa` fallback. Immediate win.
2. **Static backend in capa-cpp**: Zydis + seeded code recovery + static feature extractor
   + static driver + `--scan-code-manifest` mode + record-JSON emitter + render params.
3. **Timeline**: add `position` to capa-cpp JSON; decouple `--calls`; repoint the
   capability timeline.
4. **Cleanup**: remove Python capa, the submodule, and the `.venv` capa install; optional
   com/ GUID parity.

## Verification

- **Dynamic parity**: `capa-cpp meta.ttd.json -r capa/rules` vs
  `python -m capa.main -f ttd -r capa/rules <report>` — compare matched rule set and
  per-rule counts; `-j` diff of `rules` keys + `feature_counts` + `layout`.
- **Static parity**: `ttd-capa.py trace.run rules --code-only --keep-dumps` to produce a
  manifest+dumps, then compare `ttd_static_scan.py` against `capa-cpp --scan-code-manifest`
  on the same dumps — matched rule set per region should agree (allowing for the
  documented API-resolution gap).
- **Timeline**: `ttd-timeline.py report.ttd.json --calls` and `-r rules` render without a
  capa import; spot-check TTD positions in WinDbg.
- **Perf**: `CAPA_CPP_TIMING=1` for capa-cpp per-phase timings.
