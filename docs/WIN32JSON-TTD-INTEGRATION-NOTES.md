# win32metadata → TTD Integration Notes

Notes from a read of Microsoft's [win32metadata](https://github.com/microsoft/win32metadata) repo,
oriented around one question: **can a Time Travel Debugging tool use this metadata to decode
function parameters at runtime, given only a function name and the register/stack state?**

Short answer: yes for exported flat Win32 APIs, with caveats for COM, callbacks, and variadics.
The metadata supplies *types and semantics*; the ABI decoding is the consumer's to write.

These are the survey notes that ttd-capa's argument decoding was designed from, kept because they
explain *why* it is shaped the way it is. They are not a description of ttd-capa.
**Paths beginning `docs/`, `sources/`, `generation/`, `tests/` or `apidocs/` below belong to the
win32metadata repo, not to this one**; ttd-capa's own files are named in full, as
`ttd/src/abi.cpp` is. Section 5 says which parts were built in the end, and
[ARGUMENT-DECODING.md](ARGUMENT-DECODING.md) documents what actually ships.

---

## 1. What win32metadata is (and isn't)

That repo is the **build pipeline**, not the metadata itself. No `.winmd` is checked in there.

Two layers (see its `docs/architecture.md`):

- **Scraper** — ClangSharp walks the SDK headers listed in `generation/WinSDK/Partitions`,
  emits C# into `generation/WinSDK/obj/generated`.
- **Emitter** — `sources/ClangSharpSourceToWinmd` rewrites that C# and writes
  `Windows.Win32.winmd`, an **ECMA-335** (.NET) binary.

### Where to get the actual artifact

| Option | Notes |
|---|---|
| `Microsoft.Windows.SDK.Win32Metadata` NuGet | Rename `.nupkg` → `.zip`, extract `Windows.Win32.winmd`. Canonical source. |
| [win32json](https://github.com/marlersoft/win32json) | Pre-converted JSON. Skips ECMA-335 parsing entirely. Fastest path to a prototype. |
| `Microsoft.Windows.SDK.Win32Docs` NuGet | MessagePack dict, API name → `ApiDetails`. Optional; gives per-parameter prose for tooltips. Schema: `apidocs/Microsoft.Windows.SDK.Win32Docs/ApiDetails.cs` |

Browse it with ILSpy to get a feel for the shape before writing code.

---

## 2. What the metadata gives you per function

The contract is documented in win32metadata's **`docs/projections.md`** — that file is the spec
for everything below, and was the single most useful thing in that repo for this work.

| Need at runtime | Metadata source |
|---|---|
| Param count, order, names, types | ECMA-335 method signature + `Param` rows |
| DLL, entry point, calling convention, `SetLastError` | `[DllImport]` |
| Direction / nullability | `[In]`, `[Out]` (both = in/out), `[Optional]`, `[Reserved]`, `[RetVal]` |
| **Buffer element count** | `[NativeArrayInfo(CountParamIndex=N)]`, or `CountConst`, or `CountFieldName` |
| **Byte size of a `void*`** | `[MemorySize(BytesParamIndex=N)]` |
| String encoding (ANSI vs UTF-16) | `[Ansi]` / `[Unicode]` on the -A/-W variant |
| Decode opaque `uint` → flag names | `[AssociatedEnum]` (authored in `generation/WinSDK/enums.json`) |
| Handle type, lifetime, invalid values | `NativeTypedef` + `RAIIFree`, `InvalidHandleValue`, `DoNotRelease`, `FreeWith` |
| Arch-specific layouts (e.g. `CONTEXT`) | `[SupportedArchitecture]` |
| Struct size field to populate/validate | `[StructSizeField("cbSize")]` |
| Bitfield members | `[NativeBitfield]` on `_bitfieldN` backing fields |

### The high-value one: `CountParamIndex`

This is what makes the integration worth doing. At a `ReadFile` entry we don't merely know
`lpBuffer` is a pointer — we know its length is in `nNumberOfBytesToRead` (R8 on x64). Because
TTD can also read memory at the **return** position, `[Out]` buffers can be rendered *filled in*,
which a live debugger can't easily do.

### Reference parser

`sources/MetadataUtils/WinmdUtils.cs` is a compact, readable example of pulling this out with
`System.Reflection.Metadata` — `GetDllImports()`, `DecodeSignature`, `GetParameters()`.
Roughly 150 lines gets to usable signatures. `sources/WinmdUtils/Program.cs` wraps it in a CLI.

---

## 3. What the metadata does NOT give you

**ABI classification — this is the bulk of the work.**
Metadata gives types and order. Mapping those onto the calling convention is the consumer's to
write; in this repo that is `ttd/src/abi.cpp`:

- x64: RCX/RDX/R8/R9, then stack at `rsp+0x28`; XMM0–3 for floats; structs >8 bytes (or not
  1/2/4/8) passed by hidden pointer; return in RAX, or XMM0, or hidden first arg for large structs.
- x86: stdcall vs cdecl differ in cleanup, `[DllImport]` tells us which.
- ARM64: X0–X7, different struct rules again.

The metadata *does* provide the struct definitions needed to compute sizes and therefore decide
by-value vs by-reference — but the classifier is not metadata, it is code.

**Struct field offsets.** The metadata carries `StructLayout`, packing, field order, and explicit
`[FieldOffset]` for unions. Actual byte offsets must be computed, per architecture. ttd-capa does
not do this: struct parameters are recorded as pointers and are not expanded.

---

## 4. Practical gotchas

1. **API sets break naive module matching.** Metadata says `CreateFileW` → `kernel32.dll`;
   TTD will show `KERNELBASE.dll!CreateFileW`. **Key the index on function name first**, treat
   module as a weak disambiguator only.
2. **Coverage is public SDK only.** No `ntdll` internals or undocumented APIs. Kernel-mode/driver
   APIs are in the sibling [wdkmetadata](https://github.com/microsoft/wdkmetadata) repo, same tooling.
3. **Name collisions.** The same name can appear in multiple namespaces; A/W variants are separate
   entries. `generation/WinSDK/libMappings.rsp` (~26k `Func=Dll.dll` lines) helps disambiguate and
   is independently useful as a fast function→DLL table.
4. **COM.** No explicit vtable indices in the metadata. Method declaration order *is* vtable order,
   walking the `[NativeInheritance]` chain (IUnknown's 3 slots first). Workable, but requires
   knowing the interface identity at runtime. `tests/VtablesFromPdb` solves the inverse problem via
   DIA/PDBs and is worth reading before attempting this. Treat COM as a separate phase.
5. **Variadics** end in `__arglist` — arg count is not statically knowable. Needs format-string
   parsing to go further.
6. **Inline/macro APIs** (`[Constant]`-decorated) never appear as real calls, so they're moot here.
7. **Architecture matters for layout.** Resolve `[SupportedArchitecture]` against the trace's arch
   at index-build time, not at query time.

---

## 5. Integration shape

Pre-bake once; do not parse the winmd at debug time. This is the shape that was built.

```
Windows.Win32.winmd  (or win32json)
        │
        ▼
  [ offline indexer ]      ← resolves type graph, expands structs,
        │                     precomputes field offsets per arch,
        │                     flattens attributes into plain fields
        ▼
  compact SQLite / JSON     keyed by (function name, module?, arch)
        │
        ▼
  TTD extension  ──►  ABI decoder (ours)  ──►  rendered parameters
```

Optionally join `Microsoft.Windows.SDK.Win32Docs` in at index-build time for parameter
descriptions. ttd-capa does not; it takes the win32json route instead.

### How it came out

The offline indexer is `tools/build-win32-index.py`, which emits the binary
`ttd/data/win32-index.bin`; `tools/build-phnt-index.py` does the same for the native API. The
decoder is `ttd/src/abi.cpp`, covering x64 and x86.

| Piece | Status |
|---|---|
| winmd (via win32json) → flat binary index | built |
| x64 and x86 ABI decoder | built; the bulk of the work, as expected |
| `CountParamIndex` / `MemorySize` buffers, out-params read at the return | built; the highest payoff, also as expected |
| `AssociatedEnum` flag and enum names | built |
| Struct field expansion | not built — struct parameters stay pointers |
| COM vtable resolution | not built; still a separate project |
| Variadics past the fixed parameters | not built, for the reason in section 4 |

---

## 6. Key files to revisit (all in win32metadata)

| Path | Why |
|---|---|
| `docs/projections.md` | **The attribute contract.** Start here. |
| `docs/architecture.md` | How the winmd is produced |
| `sources/MetadataUtils/WinmdUtils.cs` | Reference winmd parser |
| `sources/WinmdUtils/Program.cs` | CLI wrapping the above |
| `generation/WinSDK/libMappings.rsp` | ~26k function → DLL mappings |
| `generation/WinSDK/enums.json` | Source of `[AssociatedEnum]` param associations |
| `tests/VtablesFromPdb/Program.cs` | PDB/DIA vtable extraction, relevant to COM |
| `apidocs/.../ApiDetails.cs` | Shape of the docs package |
