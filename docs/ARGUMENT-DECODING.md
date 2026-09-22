# Metadata-driven argument decoding

Knowing an API's name is not the same as knowing its signature. Without one, an extractor can
only read the four x64 argument registers and guess at each value, so `CloseHandle(hObject)` gets
recorded with four arguments, three of which are whatever the caller left in RDX/R8/R9, and any
integer that happens to point at printable bytes is mistaken for a string.

ttd-capa decodes arguments from API metadata instead. Two binary indexes ship next to the
extractor in `ttd/data/`, and both are generated from vendored submodules.

## The Win32 index

[win32json](https://github.com/marlersoft/win32json) is Microsoft's Win32 API metadata.
`tools/build-win32-index.py` flattens its ~300 JSON files into `ttd/data/win32-index.bin`
(~2.7 MB), keyed by export name, which the extractor memory-maps at startup. For every call whose
export is in the index, ttd-capa knows:

- **the real parameter count**, so exactly that many arguments are captured, including those past
  RCX/RDX/R8/R9 (`CreateProcessW` has ten) and none of the register residue that would otherwise
  be reported as an argument
- **each parameter's type**, so `PSTR` is decoded as ANSI and `PWSTR` as UTF-16 rather than by
  trial, and values typed as `HANDLE`, enums, or plain integers are never dereferenced
- **direction**, so `[Out]` parameters are re-read at the call's *return* position and
  `lpNumberOfBytesRead` and similar are rendered filled in
- **buffer lengths**, from `MemorySize(BytesParamIndex)` and array count parameters, so
  `InternetReadFile`'s `lpBuffer` is captured at its true length once the callee has written it
- **enum and flag tables**, so `dwCreationDisposition=3` renders as `CREATE_ALWAYS`

## The native API index

win32json documents the public Windows SDK: 17,148 functions, only 89 of them imported from
ntdll. In a real trace that gap is most of the calls. 59% of the API calls in a Windows Media
Player trace had no prototype, and 344 of the 570 distinct functions missing were ntdll exports.

So there is a second index built from a second source. [phnt](https://github.com/winsiderss/phnt)
is the native API header set maintained for System Informer (MIT licensed);
`tools/build-phnt-index.py` parses its 2,492 declarations into `ttd/data/phnt-index.bin` in the
same binary format. The SAL annotations map onto fields the index already carried, so
`_Out_writes_bytes_(Length)` becomes an out-parameter whose length lives in the parameter named
`Length`.

The two are merged at load time, and win32json wins wherever it has an answer: an index built
from official metadata is richer than one recovered from headers, and it is the only one of the
two that carries enum tables. phnt fills gaps and replaces entries the generator flagged
unsupported.

| trace | calls with no prototype, before | after |
|---|---:|---:|
| wmplayer | 59.1% | 6.9% |
| mimikatz | 48.2% | 14.9% |
| Cobalt Strike beacon | 84.0% | 4.6% |
| regsvr32 | 89.7% | 3.1% |

Three small tables in `ttd/src/builtinsigs.cpp` cover what neither generator can:

- the `win32u` syscall stubs, which are not in phnt's `ntuser.h`. `NtUserGetAsyncKeyState` alone
  was 576,705 calls in one desktop trace
- the C runtime (`memset`, `wcslen`, `_vsnprintf`), which is standard C that no Windows metadata
  describes
- a flag overlay, because phnt types every flag argument as a bare `ULONG`. It names the
  win32json enum table for the arguments an analyst reads, so `NtProtectVirtualMemory`'s
  `NewProtection` renders as `PAGE_EXECUTE_READWRITE` rather than `64`

The native API carries most of its text in counted descriptors rather than NUL-terminated
strings, so `UNICODE_STRING*` and `ANSI_STRING*` are decoded as kinds of their own, read by the
length the descriptor states, since the buffer need not be terminated. That is what turns
`LdrLoadDll` into `DllName='KERNEL32.dll'` and `LdrGetProcedureAddressForCaller` into
`ProcedureName='LocalFree'`, making dynamic API resolution legible.

What is left unsignatured is about 6.9% of calls, and it is what has no public source at all:
`fwbase` firewall plumbing, `__chkstk`, and internal helpers in `kernelbase`, `apphelp` and
`rpcrt4`. Those fall back to the four-register heuristic and say so with `signature: false`.

## What lands in the report

The decoded view lands in a `params` array on each call. The `args` array capa matches against
keeps its original shape; it just has the correct arity, plus any strings recovered from `[Out]`
parameters. Symbolic flag names are deliberately not pushed into `args`, since existing rules
match flags numerically.

Four keys keep "we do not know" from being reported as a value:

- `param.str_truncated` - the string stopped before its NUL terminator. A trace records only the
  bytes the guest actually touched, so a name the loader compared eight bytes at a time is
  recorded eight bytes long, and `'WakeAllC'` would otherwise be indistinguishable from a genuine
  eight-character export like `'ReadFile'`. The readers follow recorded-range seams first and only
  set this when the remaining bytes were never recorded
- `param.derefFlags` - flag names for what a pointer parameter *points at*, read at the call's
  return. `flags` still means "this argument decodes to these", so an out-pointer like
  `VirtualProtect`'s `lpflOldProtect` reports the protection that was actually replaced instead of
  a bit-decomposition of the stack address it was passed
- `call.signature: false` - there was no prototype, so the `args` values are a fixed grab of
  argument registers and some of them are whatever the previous call left behind. Absent when the
  call was decoded from a real signature
- `call.returnPosition` - where the call returned, in the same `Sequence:Steps` form as
  `position`. Together they give the call's interval, which is what separates a wrapper
  dispatching to a syscall from two adjacent operations: an inner call is one whose `position`
  falls inside that interval on the same thread. Absent, never `"0:0"`, when the call never
  returned, since a call still running at the end of the trace is a real state rather than an
  instant return

Two things are kept out of `args`, which is the matcher's view, while staying in `params`, which
is the reader's. A string marked `str_truncated` is a prefix of the real value, and matching a
rule against a prefix matches an artifact of what the trace recorded: `api-ms-win-e` is a cut-off
`api-ms-win-core-...` module name and satisfies alternations the whole name does not. And a
parameter a prototype types as `void*` is not string-sniffed at all, because `void*` is not
missing information, it is a statement that the pointee has no type. Guessing over it produced
33,526 strings in one trace, almost all of them `memset`'s uninitialised destination and the
block `RtlFreeHeap` was releasing.

## Reading a string the sweep cannot see

Knowing a parameter is a string is not the same as being able to read it. The sweep decodes
arguments inside a TTD call/return callback, and the memory view a callback is handed answers at
one fidelity only. Microsoft's header says so at `IReplayEngine.h:1436-1441`: `ThreadLocal` is a
"quick query that concentrates on the current position and current thread, possibly ignoring some
of the memory observed by other threads, along with memory observed by the current thread in the
past or future", and "this is the policy used when querying memory from the IThreadView interface
as provided to a callback".

So whether a string argument can be read at the call depends on whether that thread happened to
touch those bytes near that moment. Strings in a module image and buffers on the stack are touched
constantly and read fine. A heap buffer the caller filled long ago does not, and comes back empty.
It is not missing from the trace: a cursor parked at the same position and asked at any other
policy returns it, which is why WinDbg shows the value when the report does not.

A Cobalt Strike beacon shows the shape of it. At its first check-in the config strings are
invisible:

```
27BB:380  wininet.InternetConnectA(lpszServerName=0xcdbc10, ...)
```

Reading `0xcdbc10` at exactly that position, by policy:

```
ThreadLocal              Size=0    (nothing)
GloballyConservative     Size=64   '192.168.81.129'
GloballyAggressive       Size=64   '192.168.81.129'
```

Visibility begins at `27BB:4A4`, a few hundred steps *into* the call, where wininet reads the name
for itself. From then on the buffer stays thread-locally visible, so the second, third and fourth
check-ins decoded correctly all along. That is what made this look like a property of the trace
rather than of where we were standing when we asked.

### Asking again at the return, for free

The metadata says which parameters are strings, so the sweep knows exactly what it failed to read.
That turns out to be most of the answer, because the thread view *accumulates* as the replay runs:
it knows what this thread has touched so far. And a callee handed a string reads it -- that is what
the argument is for. `InternetConnectA` reads its server name at `27BB:4A4`, a few hundred steps
past the call.

The sweep is already standing past that read when the call returns, on the same thread, with the
same view. So each call carries the string parameters its entry could not read, and the return
callback asks again. No seek, no second cursor, nothing to position: one extra memory read on a
thread view we were handed anyway. On the beacon trace this alone settles 1,297 of the 1,584
misses, and the extractor reports that count on its own line -- it is the larger half of the
recovery and the free half, and a log crediting only the seeking pass's 91 describes a mechanism
doing a fifteenth of its actual work.

Only `[In]` parameters are carried this way. An `[Out]` string is already deferred into the
pending-out list by `decodeArgs`, above the same address threshold, and `resolvePendingOuts` reads
it at this same return through the same reader a few lines later -- so listing it here too read
every such parameter twice and threw the first answer away. That was 1,103 duplicated reads of
2,400 on the beacon trace.

A string read here is deliberately *not* marked `at_return`, although the read happens at the
return. That flag exists so a consumer can tell a pre-call value from a post-call one, and every
parameter reaching this path is `[In]`: the callee does not write it, so the bytes are the
caller's input and they describe the moment of the call. Reading them later is how the value was
recovered, not when it became true. Marking them would put an `@ret` on most string arguments in
`ttd-timeline.py` -- `lpszServerName='192.168.81.129'@ret` on an `InternetConnectA` -- which reads
as "this was an output of the call" and is exactly the confusion the flag is meant to prevent.

The seeking pass below does mark what it reads at a return, because there the position is only
used for `[Out]` parameters, whose value genuinely does not exist until the callee has run.

It will not do on its own, for a reason worth keeping. A thread view knows the bytes its thread
touched, and a comparison stops at the first character that differs, so `_wcsicmp` against
`'IEXPLORE.EXE'` leaves `'IEXP'` touched and nothing more. Read at the return, 60 parameters came
back as short prefixes of names a cursor read in full. A prefix is not a cheaper version of the
value, it is a different string: `toCapaArgs` drops anything marked `str_truncated`, so taking it
would look like progress while producing something capa refuses to match on. The return read
therefore declines a truncated result and leaves the parameter unread.

### The seeking pass, for the rest

Whatever is still unread after the sweep gets the expensive treatment: sort the remaining misses
by position, walk a cursor forward through them, and re-read each at `GloballyConservative`, which
is not held to one thread's reading. On the beacon trace that is 287 parameters rather than 1,584,
and it recovers 91 of them. Recovered strings go into `params` and into the `args` array capa
matches on, so they are evidence and not just display.

Three guards matter. A `Globally*` policy answers "mapped but not recorded here" with a buffer of
zeros rather than a short read, which for a string is a NUL in byte zero, so an empty result is
rejected rather than recorded as a value. An address below 64 KiB is skipped
before the seek, because a `PSTR` parameter holding a small integer is a `MAKEINTRESOURCE` id
rather than a pointer, and no amount of re-reading will make it text. And an `[Out]` parameter on
a call with no recorded return is skipped outright rather than read at the call position: the call
position is the one place an output buffer is guaranteed *not* to hold the callee's output, so
reading there returns whatever the buffer held from its previous use and files it as the value.
A call has no return position when it never returned -- still in flight at the end of the trace,
the process died inside it, or the return went unmatched, which SEH unwinds and tail calls cause.
That is 25 calls of 91,455 on the beacon trace. Skipping also skips `[In,Out]` strings on those
calls, where the caller's input really is at the call position; `DecodedArg` carries `is_out` and
no `is_in`, so the two cannot be told apart here, and a missing parameter beats a stale one.

The pass polls the host's cancellation predicate on every iteration rather than on the sweep's
interval. The sweep's interval is sized for the millions of call/return events it sees; this loop
runs over a few hundred misses, so any interval wider than one would fire at the first miss and
never again. It is also the seek-bound part of extraction, which makes it the part a host most
wants to be able to stop -- and a cancel here returns `Cancelled`, the same as one during the
sweep, because `ttdcapa.h` promises a cancelled pass produces no output and a report silently
missing some of its strings is not a report anyone asked for.

### What it costs and what is left

| beacon trace (75 MB, 91,455 calls) | extraction | strings decoded | complete enough for capa |
|---|---:|---:|---:|
| no recovery | 4.0 s | 84.8% | 8,095 |
| seeking pass only | 29.3 s | 94.5% | 9,161 |
| return read only (the default) | 2.2 s | 96.5% | 9,392 |
| return read, then seeking pass (`--recover-strings`) | 6.7 s | 97.3% | 9,481 |

Only the last two rows are reachable with a flag. The first two required code changes to measure
and are here for the comparison, so do not read "no recovery" as what a default run gives you --
the return read always happens, which is most of the benefit for none of the cost. That is why
the seeking pass is the part that is opt-in. "Complete enough for capa" counts string-kind parameters carrying a decoded string that
is not marked truncated, which is what `toCapaArgs` promotes into `args`.

Reading at the return first is not a cheaper approximation of seeking: it is better on both axes,
because the moment a callee reads its own argument is the moment the value is most readable. Doing
it first also leaves the seeking pass little to do, which is where the time went. `mimikatz02.run`
behaves the same way, 17.0 s down to 6.5 s with 54 misses left instead of 446.

`--recover-strings` adds the seeking pass, and `recover_strings` on `ttdcapa_extract_options`
does the same for an embedding host. Both default to off, because the pass costs more than
everything else in the extraction together and buys about one percent. The return read is free
and strictly better, so it always runs and neither option affects it.

What never comes back is mostly what was never a string. The beacon trace ends with 300 parameters
still pointers, led by `LdrResFindResourceDirectory`'s `Type` and `Name` (resource ids),
`setsockopt`'s `optval` (a binary option value the metadata types as `PSTR`), and
`RtlGetCurrentTransaction`'s two `PCWSTR` parameters, which phnt declares that way at
`phnt/ntrtl.h:7280` although the function takes none.

Separately, about 6,900 strings in that trace are recorded truncated by the entry read and stay
that way. They have the same cause and would respond to the same treatment, but completing them
all costs a seek each, so they are left alone for now.

`tests/test_string_recovery.py` guards this, because the failure is silent: a regression does not
crash, it just quietly drops strings that capa then never matches on.

Measured on the way, in case either looks tempting later: replaying forward to each position
rather than seeking to it is no cheaper (22.6 s against 22.3 s for the same 1,673 positions), and
setting a stronger policy on the sweep cursor does not reach the thread view its callbacks get --
that view is fixed at `ThreadLocal`, which is the whole reason this section exists.

### The zero-fill hazard, and why nothing here can detect it

There is a hole in the seeking pass that cannot be closed with this SDK, and it is worth writing
down so nobody spends a day rediscovering that.

`readAnsiString` stops at the first zero byte and calls the string complete. On the seeking path
those bytes come from `GloballyConservative`, which fabricates zeros for memory it knows is mapped
but has no recorded value for. So a buffer whose first few bytes were recorded and whose tail was
not reads back as a short, clean, apparently-terminated string, reported as complete -- exactly
the outcome `str_truncated` exists to prevent, and exactly the prefix that satisfies rule
alternations the whole value does not. `ThreadLocal` is honest about this and returns nothing for
unrecorded bytes, so the free return-pass read is not exposed; only the seeking pass is.

The fix that suggests itself is to check the terminator against `QueryMemoryBufferWithRanges`,
which reports the ranges a query actually covered. It does not work. Measured over all 287
recovery sites on `beacon_x6401.run`:

- `QueryMemoryBuffer` at `GloballyConservative` returned the **full** 512 bytes requested at every
  one of the 287 sites. It never short-reads, so the gap-crossing loop in `readRecordedRun` never
  runs on this path and the seam it exists for cannot arise here.
- `QueryMemoryBufferWithRanges` reported ranges tiling the **entire** 512 bytes at every site,
  sum of range sizes equal to the buffer size every time. 23 of those ranges were entirely zeros
  and were reported as covered, with ordinary-looking `Sequence` values, indistinguishable from
  the recorded ones. "Is the terminator inside a covered range" is therefore always true.
- `QueryMemoryRange` looked more promising -- it genuinely answers `Size == 0` for an address
  that was never mapped, which `QueryMemoryBuffer` does not. But walking it forward in contiguous
  blocks from each string address reached 600+ bytes in ~20 blocks at every single site, with no
  gap anywhere. It distinguishes *unmapped* from *mapped*, not *unrecorded* from *recorded*.

The only oracle the SDK documents for "is this actually recorded here" is `ThreadLocal`, and on
this path it returns nothing by construction -- being unable to see these bytes is why the seek
exists at all. So there is nothing to check the terminator against. The hazard stands, unobserved:
across the 91 strings the seeking pass recovers on the beacon trace, every all-zero span sits past
the terminator, and a scan of 227 recovered strings on two traces turned up no zero-fill
truncation either. Do not implement the ranges check; it costs a query per recovered string and
detects nothing.

## x86 traces

On x86, a signature whose argument layout cannot be pinned down falls back to heuristic capture.
This happens when a parameter is a pointer-sized typedef the metadata kept intact (`WPARAM`,
`LPARAM`), since the index stores every scalar's width measured for x64 and an 8 there could mean
either a 4-byte `UIntPtr` or a real 8-byte `Int64`. Where the metadata resolved the parameter to
a primitive, the display type settles it, so the `SIZE_T` family decodes exactly. `--dump-sig`
marks the affected signatures `[no x86 layout]` and prints the stack offset of every parameter it
can lay out.

## Regenerating the indexes

Only needed after bumping the corresponding submodule:

```powershell
python tools\build-win32-index.py
python tools\build-phnt-index.py
```
