> [!Warning]
> This project was entirely generated using Claude. I performed testing for my own use cases, but
> you may run into issues. If you do, feel free to open an issue on this repository!

# Overview

ttd-capa is a [capa](https://github.com/mandiant/capa) compatible capability extractor for Time
Travel Debugging (TTD) traces. A TTD trace records the complete execution of a process, so it
exposes behavior that a static scan of the file on disk can't see. Rule matching uses capa-cpp (the
`capa-cpp/` submodule), a C++ rewrite of capa that runs several times faster than the official
Python version.

![](assets/ttd-capa-comparison.png)

A static capa scan of a packed sample (left) typically identifies the packer and little else,
because the real code is not present in the file. ttd-capa scans the recorded execution instead,
so capabilities that exist only after unpacking are recovered (right).

# How it works

![](assets/ttd-capa-diagram.png)

1. Record a TTD trace of the sample
2. Run `ttdcapa-extract.exe` on the trace. It replays the trace and writes a capa-compatible JSON
   report
3. Match that report against the capa rules with `capa-cpp`, which surfaces the capabilities

The extractor is built on Microsoft's TTD C++ SDK and
[nlohmann/json](https://github.com/nlohmann/json). The trace's module load events give the address,
name and owning module of every exported function. The extractor replays the trace with an execute
watchpoint on each of those addresses and records a call when a thread enters an export right after
a `call`, with that call's return address on top of the stack. Each record holds the module, the
function, the arguments, the return value and the trace position of the `call` instruction.

Recording at the export also catches calls that reach an API through a jump: the Control Flow Guard
dispatcher that CFG-compiled system DLLs use for function pointers, a stub, or an export table
redirected to a sample's own thunks. These calls carry a `via` field with the address the `call`
landed on. The return-address check rejects code that only jumps to an export, such as a
return-address-spoofing gadget. Thread starts are not recorded: the call from
`BaseThreadInitThunk` to a start routine is Windows starting the thread, even when the start
address is an export.

A call that arrives through a jump at an export that only returns (`ret`, or `xor eax,eax; ret`)
is marked `ambiguous`. The linker folds identical functions into one copy, so that address is
usually shared with functions that are not exported, and the export's name may be wrong.

Arguments are decoded from API metadata. Two binary indexes ship with the extractor, one built from
[win32json](https://github.com/marlersoft/win32json) (Microsoft's Win32 metadata) and one from
[phnt](https://github.com/winsiderss/phnt) (native API headers). They supply each call's parameter
count and types, so flags and enums print by name and `[Out]` parameters are read after the callee
fills them in. A call with no signature falls back to a heuristic: the four argument registers on
x64, or the first four stack words on x86. Those calls are marked `signature: false`.

A replay only sees memory the calling thread has already touched, so a string prepared earlier can
read back as nothing. Most such strings are read again when the call returns, after the callee has
touched them. Recovering the rest means seeking back to each call, which costs more than the rest
of the extraction, so it only runs with `--recover-strings`.

Code the program creates at runtime, where a packer or loader keeps the interesting part, makes no
API calls to watch. `--scan-code` adds a pass for it. The pass watches for memory that is
allocated, mapped or made executable and then run, and rebuilds each region's contents as they
stood when its code ran, one `.bin` snapshot per generation, so a multi-stage loader yields one
snapshot per stage. capa-cpp runs its static analysis over the snapshots, starting disassembly from
the instruction addresses the trace shows were executed. A further replay with execute watchpoints
on the matched addresses places each code capability at the moment it ran.

# Prerequisites

- Windows
- Visual Studio with the v145 MSVC build tools and C++20
- WinDbg or TTD CLI installed, for the TTD replay DLLs (`TTDReplay.dll` and `TTDReplayCPU.dll`)
- Python 3.10+, for the wrapper scripts
- vcpkg, to build capa-cpp

# Building

Clone, then initialise the submodules:

```powershell
git clone <repo-url> ttd-capa
cd ttd-capa
git submodule update --init
```

They supply `win32json` and `phnt` (API metadata for argument decoding), `capa-cpp` (the matcher)
and `rules` (the capa rule collection).

Avoid `--recursive`: it also pulls capa-cpp's IDA SDK submodule, which only its IDA plugin uses.

## ttd-capa

1. Open `ttd/ttdcapa-extract.sln` in Visual Studio.
2. Ensure the required NuGet packages (`Microsoft.TimeTravelDebugging.Apis` and `nlohmann.json`)
   are installed.
3. Set the configuration to `Release` and the platform to `x64`.
4. Build the solution.

This produces two outputs in `ttd/bin/x64/Release/`:

- `ttdcapa-extract.exe`, the command-line tool the wrapper scripts drive
- `ttdcapa.dll` (plus `ttdcapa.lib`), the same analysis passes behind a C ABI, for embedding in
  another program

To build just one from the command line, in a Developer PowerShell for VS (`MSBuild` and `vcpkg`
are not on the default PATH):

```powershell
MSBuild ttd\ttdcapa-extract.vcxproj -p:Configuration=Release -p:Platform=x64   # the tool
MSBuild ttd\ttdcapa.vcxproj         -p:Configuration=Release -p:Platform=x64   # the DLL
```

The build copies `ttd/data/win32-index.bin` and `ttd/data/phnt-index.bin` next to the output, and
warns if either is missing. Regenerate them with `python tools\build-win32-index.py` and
`python tools\build-phnt-index.py`. Without them the extractor still runs, but falls back to
heuristic argument capture.

The extractor also needs Microsoft's `TTDReplay.dll` and `TTDReplayCPU.dll` in the same directory
as `ttdcapa-extract.exe`. The build copies them automatically from `TTDRuntimeDir`, which defaults
to the TTD NuGet package's `build\native\bin\x64`. If that folder does not carry them, point the
build at a copy:

```powershell
MSBuild ttd\ttdcapa-extract.vcxproj -p:Configuration=Release -p:Platform=x64 -p:TTDRuntimeDir=<dir>
```

Copying both DLLs next to `ttdcapa-extract.exe` by hand works too. A WinDbg installation is
one place to get them:

```powershell
Join-Path (Get-AppxPackage Microsoft.WinDbg).InstallLocation 'amd64\ttd'
```

## capa-cpp

Build the matcher once, with Visual Studio 2022/2026 (MSVC v143/v145, C++20) and vcpkg. The
`vcpkg.json` manifest lives in the submodule's inner `capa-cpp\` project directory, which is what
`--x-manifest-root` has to point at:

```powershell
cd capa-cpp
vcpkg install --triplet x64-windows-static --x-manifest-root=capa-cpp
MSBuild capa-cpp\capa-cpp.vcxproj -p:Configuration=Release -p:Platform=x64
# (or ./build.sh Release from Git Bash)
```

This produces a self-contained `capa-cpp.exe`. The wrapper scripts find the most recently built
copy on their own; a copy next to the scripts takes precedence, and `--capa-cpp <path>` names one
explicitly. See `capa-cpp/README.md` for more.

# Usage

## Wrapper script

`ttd-capa.py` runs the extractor and the matcher in one step.

```powershell
python ttd-capa.py <trace.run> <rules-dir> [--sample sample.exe] [-- <capa-cpp args>]
```

By default the TTD report goes to a temp file that is deleted after the match. To keep it for other
tools, such as the timeline script, pass `--json-output <path>`, or `--keep-json` to leave the temp
file in place. Either way the path is printed to stderr.

```powershell
python ttd-capa.py <trace.run> <rules-dir> --json-output report.ttd.json
```

Anything after a bare `--` is forwarded to capa-cpp, for example `-vv` for the full match tree or
`-j` for a JSON ResultDocument:

```powershell
python ttd-capa.py <trace.run> <rules-dir> --sample sample.exe -- -vv
```

Common flags:

- `--sample <path>`: the on-disk sample, for accurate hashes in the report
- `--extractor <path>` / `--capa-cpp <path>`: use these binaries instead of searching for them
- `--json-output <path>`: write the TTD report to a known path and keep it
- `--keep-json`: keep the report in a temp file (path printed to stderr)
- `--max-calls N`: cap recorded calls, for very large traces
- `--max-buffer N`: bytes kept from any one captured buffer (default 256)
- `--no-metadata`: use the heuristic capture for every call
- `--recover-strings`: decode about 1% more string arguments at roughly three times the run time
  (2.2s to 6.7s on a 75 MB trace). Useful when a rule depends on a string left as a pointer; see
  [docs/ARGUMENT-DECODING.md](docs/ARGUMENT-DECODING.md)
- `--with-stack-args`: for calls with no metadata, read four more stack slots
- `--win32-index <path>`: use a specific `win32-index.bin`
- `--rebuild-index`: delete an unloadable `.idx` and build a fresh one. Try this when a run is
  unexpectedly slow: the TTD SDK does not replace a stale index on its own, and replays unindexed

## Manual

```powershell
# 1) generate the report from the trace
<ttdcapa-extract.exe> <trace.run> --sample <optional sample> -o report.ttd.json

# 2) match the report against capa rules
<capa-cpp.exe> report.ttd.json -r <rules-dir>
```

## Scanning runtime code

The dynamic pass matches API calls, so it is blind to code a packer or loader unpacks or injects at
runtime. `--scan-code` adds the reconstruction pass described above.

```powershell
# dynamic run, then reconstruct and static-scan the executable regions
python ttd-capa.py <trace.run> <rules-dir> --scan-code

# only the code scan, keeping the dumps for triage
python ttd-capa.py <trace.run> <rules-dir> --code-only --keep-dumps
```

Flags:

- `--code-only`: skip the dynamic call report
- `--max-code-scans N`: cap snapshots reconstructed per region (default 8; 0 = unlimited)
- `--scan-data`: also reconstruct and scan non-executable regions
- `--no-scan-modules`: do not watch the sample's own module images
- `--keep-dumps`: keep the reconstructed `.bin` snapshots
- `--code-output <path>`: write the static capability records as JSON, for `ttd-timeline.py --code`
- `--code-hits-output <path>`: also record where each matched code site executed
- `--max-region-bytes N` / `--max-write-log-bytes N`: memory budgets (defaults 256 MiB per region,
  1 GiB across all regions). Anything over budget is skipped with a diagnostic

The two views are complementary. The dynamic pass owns API-name features, which a reconstructed
region cannot supply because it has no import table. The static pass adds code-structure
capabilities the call sweep cannot see, such as crypto constants, stack strings, and embedded PEs.
See [docs/CODE-SCAN.md](docs/CODE-SCAN.md) for how the pass works and how to run it manually.

## Unified report

`--summary` runs both passes and prints one source-tagged report, with ATT&CK and MBC roll-ups and
a static-code detail listing (region, offset, and first TTD position) for triage:

```powershell
python ttd-capa.py <trace.run> <rules-dir> --summary
```

Each capability is tagged `dyn` (matched on API calls), `code` (matched in reconstructed code), or
`both`, with per-source match counts:

```
  68 unique capabilities: 50 from API calls, 39 from reconstructed code (3 region(s)), 21 seen by both.
...
Capability                                Namespace                                        Src   Dyn  Code
-----------------------------------------------------------------------------------------------------------
reference analysis tools strings          anti-analysis                                    code    -     9
check SystemKernelDebuggerInformation     anti-analysis/anti-debugging/debugger-detection  dyn     1     -
packed with UPX                           anti-analysis/packer/upx                         both    1     8
```

`ttd-report.py` builds the same report from artifacts you already have, without re-running the
trace:

```powershell
python ttd-report.py <report.ttd.json> -r <rules-dir> --code code-caps.json
```

## Timeline

Because the report carries TTD positions, `ttd-timeline.py` can show capabilities in the order
they were used, with the call that triggered each one. Below are four of the 2,684 rows a 75 MB
beacon trace produces, with the name columns narrowed to fit this page:

```
TTD POS    TID  CAPABILITY                            NAMESPACE                  TRIGGERING CALL
--------------------------------------------------------------------------------------------------
1EA:6F8      2  link function at runtime on Windows   linking/runtime-linking    kernel32.GetProcAddress(hModule=0x7ffa6a130000, lpProcName='CloseHandle') -> 0x7ffa6a186e40
1EA:774      2  link function at runtime on Windows   linking/runtime-linking    ntdll.LdrGetProcedureAddressForCaller(DllHandle=0x7ffa6a130000, ProcedureName='CloseHandle', ProcedureNumber=0x0, ProcedureAddress=0x65ff18->0x7ffa6a186e40@ret, Flags=0x0, CallerAddress=0x45898e) -> 0x0
   ...
27BB:380     4  connect to HTTP server                communication/http/client  wininet.InternetConnectA(hInternet=0xcc0004, lpszServerName='192.168.81.129', nServerPort=0x50, lpszUserName=0x0, lpszPassword=0x0, dwService=0x3, dwFlags=0x0, dwContext=0x11584c4) -> 0xcc0008
   ...
27C5:5E      4  initialize WinHTTP library            communication/http         winhttp.WinHttpOpen(pszAgentW='WinHTTP global session', dwAccessType=WINHTTP_ACCESS_TYPE_NO_PROXY, pszProxyW=0x0, pszProxyBypassW=0x0, dwFlags=0x0) -> 0xd13de0
```

Parameters are named, `->` shows a pointer's pointee, `@ret` marks an `[Out]` value read after the
callee filled it in, and enums render by name. `lpszServerName` above is the beacon's C2 address,
one of the strings read at the call's return.

The timeline takes either a TTD report or a `.run` trace:

```powershell
# capabilities, from an existing report
python ttd-timeline.py report.ttd.json -r <rules-dir>

# straight from a trace, including reconstructed code capabilities
python ttd-timeline.py <trace.run> -r <rules-dir> --scan-code

# every recorded API call instead of capabilities (no rules needed)
python ttd-timeline.py report.ttd.json --calls
```

Produce the report with `ttd-capa.py --json-output report.ttd.json`, or run the extractor
directly with `-o`.

Reconstructed-code capabilities appear in the same timeline, with the triggering column naming the
region (`code@0x<address>`) instead of a call. With a `.run` trace, `--scan-code` (shown above)
extracts, matches, reconstructs and scans the regions, then replays once more so each code row sits
at the moment it ran.

`--code` and `--code-hits` build the timeline from existing artifacts instead, so a long trace is
not replayed again. `ttd-capa.py` writes them with `--code-output` and `--code-hits-output`:

```powershell
# produce the three artifacts once
python ttd-capa.py <trace.run> <rules-dir> --scan-code --json-output report.ttd.json --code-output code-caps.json --code-hits-output hits.json

# then build timelines from them without touching the trace
python ttd-timeline.py report.ttd.json -r <rules-dir> --code code-caps.json --code-hits hits.json

# code capabilities on their own, no dynamic report
python ttd-timeline.py --code code-caps.json --code-hits hits.json
```

`--code-hits` is optional. Without it, a code capability sits where its region was reconstructed
rather than where it ran, and the listing's footer marks it `region-positioned`. See
[docs/CODE-SCAN.md](docs/CODE-SCAN.md) for what the passes do.

# Embedding

The same analysis passes are available in-process through `ttdcapa.dll` and its C header,
`ttd/include/ttdcapa.h`:

```c
ttdcapa_extract_options options;
memset(&options, 0, sizeof(options));
options.struct_size       = sizeof(options);
options.common.trace_path = L"beacon.run";
options.common.log        = my_log_callback;   /* progress lines, or NULL for stderr */

ttdcapa_string report = { 0 };
if (ttdcapa_extract_report(&options, &report) == TTDCAPA_OK) {
    /* report.data is the TTD report JSON; hand it to capa-cpp */
    ttdcapa_string_free(&report);
}
```

Progress reporting is redirectable and every pass takes a cancellation callback, so a long replay
can be stopped from the UI thread. Rule matching stays capa-cpp's job either way: ttd-capa produces
the evidence. `ttd/examples/embed-demo.c` is a complete working consumer, and
[docs/EMBEDDING.md](docs/EMBEDDING.md) covers the ABI rules, the call sequence, and the output
formats.

# Supported and not supported

Supported:

- x64 and x86 traces, including WoW64. Bitness is decided per call from the target module's PE
  headers, because a WoW64 process runs both widths at once
- exact argument decoding for the public Win32 SDK surface and the native API covered by phnt
- `[Out]` parameters, counted `UNICODE_STRING` and `ANSI_STRING` descriptors, and enum and flag
  names
- static analysis of memory regions created during the recording, via `--scan-code`

Not supported:

- ARM and ARM64 traces
- functions that are not exported by a loaded module. A call to an export is still recorded when it
  reaches the export through a jump
- COM interface methods
- exact arguments for APIs with no metadata (`ntdll` internals, undocumented APIs, CRT helpers).
  These fall back to the heuristic capture described above and are marked `signature: false`
- variadic functions beyond their fixed parameters, since the argument count is not statically
  knowable
- structure fields. Structure parameters are recorded as pointers and are not expanded
- some x86 signatures, where a pointer-sized typedef such as `WPARAM` leaves the argument layout
  ambiguous. Those calls fall back to the heuristic capture
- API-name features in the `--scan-code` static pass. A reconstructed region has no import table,
  so dynamically resolved API names stay the dynamic pass's job
- regions not created during the recording. Normally loaded DLLs are out of scope for `--scan-code`
