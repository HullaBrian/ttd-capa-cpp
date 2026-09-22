# Embedding ttd-capa

ttd-capa builds as `ttdcapa.dll` alongside the `ttdcapa-extract.exe` command-line tool. Both
expose the same three analysis passes; the DLL exposes them through a stable C ABI
(`ttd/include/ttdcapa.h`) so another program can run them in-process instead of shelling out
to the executable and parsing files back off disk.

This exists for host projects that build their own view of a trace — a timeline, a
memory-scanning pass, a triage UI — and want ttd-capa's capability evidence as one input
among several.

## What ttd-capa gives you, and what it doesn't

| Pass | Entry point | Produces |
|---|---|---|
| Dynamic (API calls) | `ttdcapa_extract_report` | TTD report JSON: every call to a resolved module export, with decoded arguments and a TTD position |
| Static, part 1 (reconstruct) | `ttdcapa_scan_code` | One `.bin` per snapshot of runtime-created code, plus a manifest describing them |
| Static, part 2 (when did it run) | `ttdcapa_trace_code_hits` | Per matched instruction address, the TTD positions it executed at |

**Rule matching is not in here.** It belongs to [capa-cpp], which consumes the report JSON
from pass 1 and the manifest plus dumps from pass 2. ttd-capa produces evidence; capa-cpp
turns it into capabilities. A host integrates both.

## The flow

```
        ttdcapa_extract_report ──► report JSON ──────────► capa-cpp <report> -r rules -j
                                                                    │
                                                                    ├─► dynamic capabilities
                                                                    │   (each at a call's TTD position)
        ttdcapa_scan_code ──────► manifest + .bin dumps ──► capa-cpp --scan-code-manifest
                                                                    │
                                                                    └─► static capability records
                                                                        (each with matched `vas`)
                                                                          │
        ttdcapa_trace_code_hits ◄─────────────────────────────────────────┘
                    │
                    └─► when each matched code site actually executed
```

Passes 1 and 2 are independent and can run in either order. Pass 3 needs capa-cpp's static
records, so it comes last. `ttd-capa.py` and `ttd-timeline.py` in the repo root drive exactly
this sequence over the CLI, and are worth reading as an executable specification of it.

## Calling convention and lifetimes

- C linkage, `__cdecl`, no C++ types across the boundary, and no exception escapes: every
  entry point returns a `ttdcapa_status`.
- Every options struct begins with `struct_size`. Set it to `sizeof(the struct you compiled
  against)`; a newer library uses it to tell which fields you actually filled in, and treats
  the rest as unset.
- Zero the struct before filling it (`memset`) so unset fields read as the documented
  defaults.
- Strings come back in a `ttdcapa_string` owned by the library. Release them with
  `ttdcapa_string_free`, never `free()`.
- Paths are wide (UTF-16), because that is what the TTD engine takes. Returned text is UTF-8.
- One call analyses one trace and is not internally parallel. Calls are **not thread-safe
  against each other**: the diagnostics sink and the Win32 metadata index are process-wide.

### Diagnostics

Each pass reports progress line by line. Supply `common.log` to receive those lines
(UTF-8, no trailing newline, with a severity), or leave it NULL to let the library write to
stderr — which is what the command-line tool does. A library has no business owning a host's
error stream, so nothing is written anywhere else.

Severity separates each pass's **findings** from its **narration**:

| Level | What arrives there |
|---|---|
| `TTDCAPA_LOG_INFO` | results — the call count, the regions tracked, each region reconstructed, the snapshots written |
| `TTDCAPA_LOG_WARN` | something was skipped, approximated, truncated, or cancelled |
| `TTDCAPA_LOG_ERROR` | the pass could not do what was asked |
| `TTDCAPA_LOG_DEBUG` | narration — which stage started, how long a replay took, which export a breakpoint landed on |

`TTDCAPA_LOG_DEBUG` is **not produced at all** unless you set the pass's `verbose` option, so a
zeroed options struct gives you a log you can show a user unfiltered. It is worth the
distinction: one `--scan-code` run emits about five result lines and twenty-five narration ones,
and since each pass opens the trace independently, the setup narration repeats per pass.

Turn `verbose` on when you are diagnosing a pass rather than reading its results — the timings in
particular are what tell you whether a stage is replaying once or once per region.

`verbose` sits at the tail of each of the three options structs rather than in
`ttdcapa_common_options`: that struct is embedded *by value*, so growing it would shift every
field after it in each pass's options, and `struct_size` cannot detect that. Anything shared and
new goes at the tail of all three instead.

Appending to the tail has one trap of its own. All three structs contain `uint64_t` members and
so are 8-aligned, which means a struct ending on a 4-byte boundary carries four bytes of tail
padding. An `int` appended into that padding does not change `sizeof` — so `struct_size` stays
identical across the two layouts and cannot tell them apart, and an older host's *indeterminate*
padding gets copied in and read as a set flag, turning an option on for a caller that never asked
for it. `ttdcapa_scan_code_options` is in that shape today, which is what its `reserved0` filler
is for: it consumes the padding so `no_scan_modules` and anything after it start past the old
struct's end. Check `offsetof` against the previous `sizeof` when adding a field, rather than
assuming the tail is free.

### Cancellation

Supply `common.cancel`; it is polled during long replays and any non-zero return stops the
pass, which then returns `TTDCAPA_E_CANCELLED` and produces no output. The predicate is
called from the replay thread, so keep it to reading an atomic flag.

That covers pass 1's optional string-seeking stage as well as its sweep, which matters
because that stage is the seek-bound one -- 4.5 s of a 6.7 s run on a 75 MB trace when it is
switched on. Cancelling there returns `TTDCAPA_E_CANCELLED` like anywhere else, so a host that
wants the report built so far should leave `recover_strings` at 0 rather than cancel.

### Asking for the string recovery

`recover_strings` on `ttdcapa_extract_options` adds a stage that re-reads string arguments the
sweep could not see, at roughly triple the extraction time for about one percent more decoded
strings. It is 0 by default, which leaves a bare pointer where those strings would have been.
The recovery that happens for free at each call's own return always runs and is unaffected.
The header explains what the stage does; `ARGUMENT-DECODING.md` explains why it exists.

### The trace index

Every pass wants a loadable `.idx` next to the trace; without one the engine still replays, far
more slowly, and out-params the kernel wrote may not be recoverable. The SDK will not replace an
index file it cannot read — deleting a user's file has to be asked for — so a trace carrying a
stale index (built by a different TTD version, or truncated by an interrupted run) stays slow on
every subsequent run until something says so explicitly. Set `rebuild_index` on any pass's options
to make that request; the diagnostic explaining the situation reaches your log callback either way.

### What pass 2 watches

By default the code scan tracks two things: the regions its discovery providers turn up
(`NtAllocateVirtualMemory`, `NtMapViewOfSection`, `NtProtectVirtualMemory`) and the sample's own
module images — the main executable plus anything loaded from outside the Windows directories.
System modules are always excluded; their writes are the loader's, and forty snapshots of ntdll
teach nobody anything.

The second half exists for packers that unpack **in place**. UPX and most of its descendants
never allocate — they decompress over their own image and jump into it, and
`NtMapViewOfSection` explicitly rejects anything overlapping a loaded module. Watch only the
providers and that whole family reconstructs to nothing at all.

It is not free. A module the program writes across yields a snapshot per generation, and a busy
image can yield a great many — one trace produced 260810 snapshots on the region at
`0x400000` alone. `max_scans_per_region` caps that per region; setting `no_scan_modules`
removes the module images from the scan entirely, leaving the provider-discovered regions. Use
it when the trace is known not to need in-place-packer coverage, or when the scan's cost matters
more than catching one. The command-line equivalent is `--no-scan-modules`.

The sense is inverted on purpose: `no_scan_modules` was appended after the initial release, and
a host built against an older header leaves it 0, which keeps the module scanning that has
always been the default. As with the budgets below, a host that sets it against a library built
before the field existed silently gets the old behaviour — check the version string if you
depend on it.

### Memory

Pass 2 is the one with an appetite. Reconstructing a region holds a buffer the size of that
region plus a log of every write that landed in it, so peak memory follows the largest region
in the trace and how hard the program worked on it — not the size of the `.run` file. A packer
that decrypts a 12 MB region a few bytes at a time can log fifteen million writes.

Two budgets in `ttdcapa_scan_code_options` bound that per region: `max_region_bytes` (default
256 MiB) and `max_write_log_bytes` (default 1 GiB). A region over either is skipped, and the
reason goes to your log callback. Set them from what the host can spare; `UINT64_MAX` lifts
them entirely.

Read them as approximate. The write log's arena grows geometrically, so a log allowed to reach
the budget can transiently hold about half as much again during the reallocation that takes it
there — leave headroom rather than sizing a host to the number exactly. Should a region exhaust
the allocator anyway, that region alone is abandoned and the scan carries on: the manifest you
get back is short an entry rather than missing, and any snapshots already written for it are
left on disk unlisted, so clean the dump directory between runs if that matters to you.

These two fields were appended to `ttdcapa_scan_code_options` after the initial release. A host
that sets them against a library built before they existed gets the old unbudgeted behaviour —
`struct_size` makes that safe, not detectable — so check the library's version string if you
depend on the budgets being enforced.

## A minimal consumer

`ttd/examples/embed-demo.c` is a complete, compilable example that runs passes 1 and 2 and
routes the extractor's progress into its own logger:

```powershell
# from ttd\, after building the solution
cl /nologo /W4 /I include examples\embed-demo.c ^
   bin\x64\Release\ttdcapa.lib /Fe:bin\x64\Release\embed-demo.exe

bin\x64\Release\embed-demo.exe <trace.run> dumps
```

The shape of a call:

```c
ttdcapa_extract_options options;
memset(&options, 0, sizeof(options));
options.struct_size      = sizeof(options);
options.common.trace_path = L"beacon.run";
options.common.log        = my_log_callback;
options.common.log_user   = my_logger;
options.report_path       = L"report.ttd.json";  /* optional: also write it out */

ttdcapa_string report = { 0 };
ttdcapa_status status = ttdcapa_extract_report(&options, &report);
if (status == TTDCAPA_OK) {
    /* report.data is UTF-8 JSON of report.length bytes -- hand it to capa-cpp */
    ttdcapa_string_free(&report);
}
```

Pass 3 takes capa-cpp's static records either as a path (`records_path`) or as JSON you
already hold (`records_json`) — supply exactly one:

```c
ttdcapa_code_hits_options hits_options;
memset(&hits_options, 0, sizeof(hits_options));
hits_options.struct_size       = sizeof(hits_options);
hits_options.common.trace_path = L"beacon.run";
hits_options.records_json      = capa_cpp_static_records;  /* the -o array */
hits_options.dedup             = TTDCAPA_HIT_DEDUP_VISIT;

ttdcapa_string hits = { 0 };
if (ttdcapa_trace_code_hits(&hits_options, &hits) == TTDCAPA_OK) { /* ... */ }
```

An empty result from pass 3 is a success, not an error: it means nothing that matched ever
executed (string and byte matches have no execution site at all).

## Linking

- **Import library**: link `bin\x64\Release\ttdcapa.lib` and include `ttd/include/ttdcapa.h`.
  Nothing else from `ttd/src/` is part of the contract.
- **Dynamic load**: resolve the exports by name after `LoadLibraryW`. Check
  `ttdcapa_abi_version()` against `TTDCAPA_ABI_VERSION` before using the rest.
- **Static**: compile the sources listed in `ttd/ttdcapa-common.props` into your own target
  and define `TTDCAPA_STATIC` so `TTDCAPA_API` expands to nothing.

At run time `ttdcapa.dll` needs Microsoft's `TTDReplay.dll` and `TTDReplayCPU.dll` findable
by the usual DLL search order — in practice, next to the executable that loads it. It also
looks for `win32-index.bin` (the Win32 metadata index) next to itself; without it, argument
decoding falls back to the four-register heuristic and everything else still works.

## Output formats

The JSON shapes are the ones the repo's Python tooling already consumes, and are the real
contract between the passes:

- **Report** (`ttdcapa_extract_report`) — `tests/sample.ttd.json` is a small fixture of it.
  Calls live under `processes[].calls[]`, each with `tid`, `seq`, `position`
  (`Sequence:Steps`, hex — paste it into WinDbg), `module`, `api`, `args`, and, where a Win32
  signature was known, a richer `params` array.
- **Manifest** (`ttdcapa_scan_code`) — `{version, trace, arch, regions[]}`, each region
  carrying `base`, `size`, `classification`, the `entries`/`executed` code seeds, and its
  `dumps[]`. Each `.bin` is a flat image of `[base, base+size)`: file offset N is virtual
  address `base+N`. `arch` is `"x86"` or `"x64"`, read from the recorded process's own PE
  headers — disassemble the dumps in that mode, since a raw image carries nothing that would
  let a decoder work its width out for itself.
- **Hits** (`ttdcapa_trace_code_hits`) — `[{va, position, tid, hits}, ...]`, one entry per
  *visit* (a continuous run of executions), not per execution. See the `hit_gap` and `dedup`
  options for how runs are split.

[capa-cpp]: ../capa-cpp/README.md
