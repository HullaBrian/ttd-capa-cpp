# Scanning runtime code (`--scan-code`)

The dynamic pass matches the API calls a trace recorded. That is blind to code a packer or loader
unpacks, JITs, or injects into private memory at runtime, which is usually where the interesting
logic is. `--scan-code` adds a second pass that reconstructs that code from the trace and runs
capa-cpp's static analysis over it.

## How the pass works

1. Replay the trace once to find every memory region the program created at runtime
   (`NtAllocateVirtualMemory` / `NtMapViewOfSection`), reclassifying any later flipped executable
   (`NtProtectVirtualMemory`). Normally loaded modules are filtered out.
2. For each executable region, do one scoped replay watching both writes and executes, and
   reconstruct the region's contents at the moments code actually ran in it. Because a capa scan
   is far more expensive than a byte-pattern scan, the trigger is execution, not writes: one
   snapshot per *writes-then-execute* generation. A one-shot unpacker yields a single snapshot;
   a multi-stage loader yields one per stage.
3. Dump each snapshot to disk along with every instruction address that executed in the region,
   and run capa-cpp's static analysis over it.

Step 3 is what makes the results useful. Plain shellcode analysis disassembles linearly from
offset 0, so a memory region whose real code sits at arbitrary offsets amid data comes back with
almost no functions, and only file-scope (string) rules match. Because the trace records exactly
which addresses ran, capa-cpp seeds its disassembler (Zydis) with them before analysis: each
executed address becomes code, and each generation-entry RIP becomes a function. That is what
lets the static pass see the unpacked routines themselves rather than only their strings.

## Memory budgets

Reconstructing a region costs a buffer of its full size plus a recording of what happened in it,
and a trace can always name a region bigger than the machine analysing it. A region over budget
is reported and skipped rather than taking the process down:

- `--max-region-bytes N` - skip regions larger than this (default 256 MiB; 0 = no limit). Per region.
- `--max-write-log-bytes N` - ceiling on the recordings of all regions together (default 1 GiB;
  0 = no limit). All regions are recorded in a single replay, so every recording is resident at
  once and their sum is what has to be bounded. When it is reached, the region holding the largest
  recording is dropped with a diagnostic and the rest of the pass continues.

Despite its name, the second budget covers a region's whole recording, not only its write log. It
used to count the write log alone, which was the whole cost back when the scan watched only
runtime-allocated regions. Since module images are watched by default, a region can be an entire
executable that the program runs for the length of the trace, and then the recording's bulk is
`executed`, one entry per distinct instruction address, which nothing counted and nothing released
when the budget dropped a region. `--no-scan-modules` removes module images from the scan
entirely, which is the cheaper answer when a trace is known not to need in-place-packer coverage.

Both take a decimal byte count, or hex with an explicit `0x` prefix (`--max-region-bytes
0x10000000`); anything else is rejected rather than half-read. Treat them as approximate: the
write log grows geometrically, so one allowed to reach its budget can briefly hold about half as
much again, and the instruction sets are counted by an estimate of what a node-based container
costs.

## Code capabilities at their real execution position

By default a code capability sits at its region's *reconstruction* position (when code first ran
there), so several can pile up at the same spot. To place each one at the moment it actually
executed, generate execute-hit records with `--code-hits-output` and pass them to the timeline via
`--code-hits`.

`ttdcapa-extract` replays the trace with an execute watchpoint on each matched instruction address
and groups the executions into *visits*: consecutive hits close together (a tight loop or one
continuous run) collapse into one row with an `(Nx)` count, while a re-execution far later starts
a new row. A routine invoked repeatedly, such as a beacon encrypting each C2 check-in, shows up
once per invocation, which reveals the cadence.

- `--hit-gap <sequences>` - TTD Sequence gap that splits executions into distinct visits
  (default 256; larger collapses more)
- `--hit-dedup visit|reentry` - `visit` (default) splits each capability by its own execution
  gaps, giving per-capability cadence; `reentry` splits by the whole region's execution bursts,
  which is coarser and answers "how many times did this unpacked region run"

String and data matches have no execution site, so they are surfaced at their region
reconstruction position and shown with a `-` thread.

```powershell
# produce both the capability records and the execution-hit records in one go
python ttd-capa.py <trace.run> <rules-dir> --code-only --code-output code-caps.json --code-hits-output hits.json

# timeline with each code capability at its real execution position
python ttd-timeline.py <report.ttd.json> -r <rules-dir> --code code-caps.json --code-hits hits.json
```

## Running the pass manually

`--scan-code` is self-contained: the extractor writes a manifest plus one `.bin` per snapshot, and
capa-cpp's `--scan-code-manifest` mode runs static analysis over them.

```powershell
# 1) reconstruct executable regions -> dump dir + manifest JSON
<ttdcapa-extract.exe> <trace.run> --scan-code --dump-dir dumps --code-manifest dumps\manifest.json

# 2) capa-static each snapshot and aggregate
<capa-cpp.exe> --scan-code-manifest dumps\manifest.json -r <rules-dir> --dumps-dir dumps -o code-caps.json
```
