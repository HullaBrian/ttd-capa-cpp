"""
Flatten the win32json Win32 API metadata into a compact binary index that
ttdcapa-extract loads at startup to decode call parameters.

The metadata (https://github.com/marlersoft/win32json, vendored as the `win32json`
submodule) is ~66 MB of JSON across ~300 files. Parsing that at debug time would be
absurd, so we pre-bake it once: resolve the type graph, classify every parameter
into an x64 ABI slot plus a small "decode kind" the C++ side can switch on, and
write a single mmap-friendly blob.

    python tools/build-win32-index.py [win32json/api] [-o ttd/data/win32-index.bin]

Regenerate whenever the win32json submodule is bumped. See
WIN32JSON-TTD-INTEGRATION-NOTES.md for what the metadata does and does not give us
(short version: types and semantics yes, ABI classification is ours -- that's the
`SLOT_*` / `classify_param` logic below).
"""
import io
import os
import sys
import json
import glob
import struct
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The record layout, the K_*/A_*/AUX_*/F_* constants and the blob writer are shared
# with tools/build-phnt-index.py, which emits the same format over a different source.
from indexformat import (  # noqa: F401  (re-exported for readability below)
    MAGIC, FORMAT_VERSION, MAX_PARAMS, NO_ENUM, StringTable, write_index,
    K_UNKNOWN, K_INTEGER, K_BOOL, K_HANDLE, K_ENUM, K_FLOAT, K_DOUBLE,
    K_ANSI_STRING, K_WIDE_STRING, K_ANSI_BUFFER, K_WIDE_BUFFER, K_BYTE_BUFFER,
    K_PTR_TO_INT, K_STRUCT_PTR, K_FUNC_PTR, K_GUID, K_POINTER,
    K_PTR_TO_ANSI_STRING, K_PTR_TO_WIDE_STRING,
    A_IN, A_OUT, A_OPTIONAL, A_CONST, A_RESERVED, A_NOT_NUL_TERM, A_NULNUL_TERM,
    A_COM_OUT_PTR, AUX_NONE, AUX_BYTES_FROM_PARAM, AUX_COUNT_FROM_PARAM,
    AUX_COUNT_CONST, F_HIDDEN_RET_PTR, F_UNSUPPORTED, F_SET_LAST_ERROR,
)

# x64 sizes for the metadata's primitive names
NATIVE_SIZE = {
    "Byte": 1, "SByte": 1, "Boolean": 1,
    "Int16": 2, "UInt16": 2, "Char": 2,
    "Int32": 4, "UInt32": 4, "Single": 4,
    "Int64": 8, "UInt64": 8, "Double": 8, "IntPtr": 8, "UIntPtr": 8,
    "Guid": 16,
    "Void": 0,
}
NATIVE_INT = {
    "Byte", "SByte", "Boolean", "Int16", "UInt16", "Char",
    "Int32", "UInt32", "Int64", "UInt64", "IntPtr", "UIntPtr",
}

# NativeTypedefs that are really strings, not opaque handles. BSTR carries a
# FreeFunc (SysFreeString) so the handle heuristic below would otherwise claim it.
STRING_TYPEDEFS = {"PSTR": K_ANSI_STRING, "PWSTR": K_WIDE_STRING, "BSTR": K_WIDE_STRING}

class Metadata:
    """The win32json type graph, plus the resolution helpers built on top of it."""

    def __init__(self, api_dir):
        self.types = {}  # (api, name) -> type dict
        self.functions = []  # (api, function dict)
        self.unicode_aliases = set()
        files = sorted(glob.glob(os.path.join(api_dir, "*.json")))
        if not files:
            sys.exit(f"no .json files under {api_dir}; is the win32json submodule checked out?")
        for path in files:
            api = os.path.basename(path)[:-5]
            with open(path, encoding="utf-8") as f:
                doc = json.load(f)
            for t in doc.get("Types", []):
                # first definition wins; arch-specific duplicates are handled by
                # SupportedArchitecture, which we resolve to x64 at index time
                self.types.setdefault((api, t["Name"]), t)
            for fn in doc.get("Functions", []):
                self.functions.append((api, fn))
            self.unicode_aliases.update(doc.get("UnicodeAliases", []))
        self._size_cache = {}

    def lookup(self, ref):
        return self.types.get((ref.get("Api"), ref.get("Name")))

    def resolve(self, t, depth=0):
        """Follow ApiRef -> NativeTypedef chains to a terminal type node.

        Returns (node, typedef) where `typedef` is the last NativeTypedef we passed
        through (or None). Callers need the typedef to spot HANDLE/PSTR, which are
        only distinguishable by name -- their definitions are plain IntPtr/Byte*.
        """
        seen = set()
        typedef = None
        while depth < 16:
            depth += 1
            if t.get("Kind") != "ApiRef":
                return t, typedef
            key = (t.get("Api"), t.get("Name"))
            if key in seen:
                return t, typedef
            seen.add(key)
            target = self.lookup(t)
            if target is None:
                return t, typedef
            if target.get("Kind") == "NativeTypedef":
                typedef = target
                t = target["Def"]
                continue
            return target, typedef
        return t, typedef

    # --- sizeof, needed only to classify by-value aggregates ------------------

    def sizeof(self, t, depth=0):
        """x64 size in bytes, or None if it can't be determined.

        Only aggregates passed/returned by value need this (236 params and 18
        return types across the whole surface), so a None here costs us one
        function, not correctness everywhere.
        """
        if depth > 24:
            return None
        kind = t.get("Kind")
        if kind == "Native":
            return NATIVE_SIZE.get(t.get("Name"))
        if kind in ("PointerTo", "LPArray", "FunctionPointer"):
            return 8
        if kind == "Array":
            child = self.sizeof(t["Child"], depth + 1)
            count = (t.get("Shape") or {}).get("Size")
            if child is None or not count:
                return None
            return child * count
        if kind == "ApiRef":
            node, _ = self.resolve(t)
            if node.get("Kind") == "ApiRef":
                return None  # unresolvable reference
            return self.sizeof(node, depth + 1)
        if kind == "Com":
            return 8
        if kind == "Enum":
            return self.enum_width(t)
        if kind in ("Struct", "Union"):
            return self._sizeof_record(t, depth)
        return None

    def _sizeof_record(self, t, depth):
        key = id(t)
        cached = self._size_cache.get(key)
        if cached is not None:
            return cached[0]
        self._size_cache[key] = (None,)  # cycle guard
        declared = t.get("Size") or 0
        if declared:
            self._size_cache[key] = (declared,)
            return declared
        pack = t.get("PackingSize") or 0
        offset = 0
        max_align = 1
        for field in t.get("Fields", []):
            fsize = self.sizeof(field["Type"], depth + 1)
            if fsize is None:
                self._size_cache[key] = (None,)
                return None
            align = min(fsize if fsize in (1, 2, 4, 8, 16) else 8, pack) if pack else fsize
            align = max(1, min(align if align in (1, 2, 4, 8, 16) else 8, 8))
            max_align = max(max_align, align)
            if t["Kind"] == "Union":
                offset = max(offset, fsize)
            else:
                offset = (offset + align - 1) // align * align + fsize
        size = (offset + max_align - 1) // max_align * max_align if offset else 0
        self._size_cache[key] = (size,)
        return size

    def enum_width(self, enum_type):
        node = enum_type
        if node.get("Kind") == "ApiRef":
            node, _ = self.resolve(node)
        integer_base = node.get("IntegerBase")
        if integer_base:
            return NATIVE_SIZE.get(integer_base, 4)
        return 4


def attr_bits(attrs):
    """Fold a param's Attrs list into a bitmask plus its MemorySize source, if any."""
    bits = 0
    bytes_param = None
    for a in attrs:
        if isinstance(a, dict):
            if a.get("Kind") == "MemorySize":
                bytes_param = a.get("BytesParamIndex")
            continue
        bits |= {
            "In": A_IN, "Out": A_OUT, "Optional": A_OPTIONAL, "Const": A_CONST,
            "Reserved": A_RESERVED, "NotNullTerminated": A_NOT_NUL_TERM,
            "NullNullTerminated": A_NULNUL_TERM, "ComOutPtr": A_COM_OUT_PTR,
        }.get(a, 0)
    return bits, bytes_param


class Param:
    # No enum index here on purpose. It is resolved separately, by
    # resolve_enum_index() at emit time, because it follows pointers to reach the
    # enum a parameter's type *ultimately* refers to -- a different question from
    # the one classify_param() answers, and the two must not be confused. There
    # used to be an enum_idx field here that nothing ever read.
    __slots__ = ("name", "type_name", "kind", "attrs", "slot",
                 "aux_kind", "aux_value", "pointee_size")

    def __init__(self):
        self.name = ""
        self.type_name = ""
        self.kind = K_UNKNOWN
        self.attrs = 0
        self.slot = 0
        self.aux_kind = AUX_NONE
        self.aux_value = 0
        self.pointee_size = 0


def type_display_name(t):
    """A short human-readable name for the report/timeline, e.g. "PWSTR", "void*"."""
    kind = t.get("Kind")
    if kind == "ApiRef":
        return t.get("Name", "")
    if kind == "Native":
        return t.get("Name", "")
    if kind == "PointerTo":
        return type_display_name(t["Child"]) + "*"
    if kind == "LPArray":
        return type_display_name(t["Child"]) + "[]"
    if kind == "FunctionPointer":
        return "fnptr"
    return kind or ""


def classify_pointee(md, child):
    """Classify what a pointer points at -> (kind, pointee_size).

    Split out because PointerTo and LPArray share it.
    """
    node, typedef = md.resolve(child)
    if typedef is not None and typedef["Name"] in STRING_TYPEDEFS:
        # e.g. PWSTR* -- an out-parameter that receives an allocated string
        return ({K_ANSI_STRING: K_PTR_TO_ANSI_STRING,
                 K_WIDE_STRING: K_PTR_TO_WIDE_STRING}[STRING_TYPEDEFS[typedef["Name"]]], 8)

    kind = node.get("Kind")
    if kind == "Native":
        name = node.get("Name")
        if name in ("Byte", "SByte"):
            return K_ANSI_BUFFER, 1
        if name == "Char":
            return K_WIDE_BUFFER, 2
        if name == "Void":
            return K_POINTER, 0
        if name == "Guid":
            return K_GUID, 16
        if name in NATIVE_INT:
            return K_PTR_TO_INT, NATIVE_SIZE[name]
        if name in ("Single", "Double"):
            return K_PTR_TO_INT, NATIVE_SIZE[name]
        return K_POINTER, 0
    if kind == "Enum":
        return K_PTR_TO_INT, md.enum_width(node)
    if kind in ("Struct", "Union", "Com"):
        return K_STRUCT_PTR, md.sizeof(node) or 0
    if kind == "FunctionPointer":
        return K_FUNC_PTR, 8
    if kind in ("PointerTo", "LPArray"):
        return K_PTR_TO_INT, 8  # void** / T** -- at least surface the inner pointer
    return K_POINTER, 0


def classify_param(md, p, enum_ids):
    """Map one metadata parameter onto a decode kind + buffer-length source.

    Returns a Param with everything except `slot` filled in (slot assignment needs
    whole-signature context and happens in build_function).
    """
    out = Param()
    out.name = p.get("Name") or ""
    t = p["Type"]
    out.type_name = type_display_name(t)
    out.attrs, bytes_param = attr_bits(p.get("Attrs") or [])

    kind = t.get("Kind")

    if kind == "LPArray":
        out.kind, out.pointee_size = classify_pointee(md, t["Child"])
        if out.kind == K_POINTER:
            out.kind = K_BYTE_BUFFER
        count_param = t.get("CountParamIndex", -1)
        count_const = t.get("CountConst", -1)
        if count_param is not None and count_param >= 0:
            out.aux_kind, out.aux_value = AUX_COUNT_FROM_PARAM, count_param
        elif count_const is not None and count_const >= 0:
            out.aux_kind, out.aux_value = AUX_COUNT_CONST, count_const

    elif kind == "PointerTo":
        out.kind, out.pointee_size = classify_pointee(md, t["Child"])

    elif kind == "ApiRef":
        node, typedef = md.resolve(t)
        if typedef is not None and typedef["Name"] in STRING_TYPEDEFS:
            out.kind = STRING_TYPEDEFS[typedef["Name"]]
            out.pointee_size = 1 if out.kind == K_ANSI_STRING else 2
        elif typedef is not None and is_handle_typedef(typedef):
            # an opaque kernel/GDI/etc handle: pointer-sized, never dereference it
            out.kind, out.pointee_size = K_HANDLE, 8
        else:
            nkind = node.get("Kind")
            if nkind == "Enum":
                out.kind = K_ENUM
                out.pointee_size = md.enum_width(node)
            elif nkind == "Native":
                out.kind, out.pointee_size = classify_native(node)
            elif nkind in ("Struct", "Union"):
                size = md.sizeof(node)
                if size in (1, 2, 4, 8):
                    out.kind, out.pointee_size = K_INTEGER, size
                elif size is None:
                    out.kind = K_UNKNOWN
                else:
                    # x64: aggregates that aren't 1/2/4/8 bytes go by hidden pointer
                    out.kind, out.pointee_size = K_STRUCT_PTR, size
            elif nkind == "Com":
                out.kind, out.pointee_size = K_POINTER, 8
            elif nkind == "FunctionPointer":
                out.kind, out.pointee_size = K_FUNC_PTR, 8
            elif nkind == "PointerTo":
                out.kind, out.pointee_size = classify_pointee(md, node["Child"])
            else:
                out.kind = K_UNKNOWN

    elif kind == "Native":
        out.kind, out.pointee_size = classify_native(t)
        if out.kind == K_GUID:
            out.kind = K_STRUCT_PTR  # 16 bytes by value -> hidden pointer on x64

    elif kind == "FunctionPointer":
        out.kind, out.pointee_size = K_FUNC_PTR, 8

    else:
        out.kind = K_UNKNOWN

    # a MemorySize attribute always wins: it says this really is a sized buffer
    if bytes_param is not None and bytes_param >= 0:
        out.aux_kind, out.aux_value = AUX_BYTES_FROM_PARAM, bytes_param
        if out.kind in (K_POINTER, K_UNKNOWN, K_STRUCT_PTR):
            out.kind = K_BYTE_BUFFER
            out.pointee_size = 1

    return out


def is_handle_typedef(typedef):
    """Is this NativeTypedef an opaque handle we must never dereference?

    RAIIFree/InvalidHandleValue mark most of them (HANDLE, HKEY, ...). The rest are
    pointer-sized H-prefixed typedefs with no lifetime metadata (HWND, HDESK, ...);
    treating those as integers would be harmless but renders worse.
    """
    if typedef.get("FreeFunc") or typedef.get("InvalidHandleValue") is not None:
        return True
    name = typedef["Name"]
    return (
        name.startswith("H")
        and typedef["Def"].get("Kind") == "Native"
        and typedef["Def"].get("Name") in ("IntPtr", "UIntPtr")
    )


def classify_native(t):
    name = t.get("Name")
    if name == "Single":
        return K_FLOAT, 4
    if name == "Double":
        return K_DOUBLE, 8
    if name == "Boolean":
        return K_BOOL, 1
    if name == "Guid":
        return K_GUID, 16
    if name == "Void":
        return K_UNKNOWN, 0
    if name in NATIVE_INT:
        return K_INTEGER, NATIVE_SIZE[name]
    return K_UNKNOWN, 0


def wants_x64(arches):
    """Architectures==[] means arch-neutral; otherwise it must list X64."""
    return not arches or "X64" in arches


def build_function(md, api, fn, enum_ids):
    """Produce (params, flags) for one function, or None if it isn't x64-relevant."""
    if not wants_x64(fn.get("Architectures") or []):
        return None

    flags = F_SET_LAST_ERROR if fn.get("SetLastError") else 0

    # A function returning an aggregate that isn't 1/2/4/8 bytes takes a hidden
    # pointer in RCX, pushing every real parameter one slot to the right.
    ret = fn.get("ReturnType") or {}
    ret_node, _ = md.resolve(ret) if ret.get("Kind") == "ApiRef" else (ret, None)
    base_slot = 0
    if ret_node.get("Kind") in ("Struct", "Union") or (
        ret_node.get("Kind") == "Native" and ret_node.get("Name") == "Guid"
    ):
        size = md.sizeof(ret_node)
        if size is None:
            flags |= F_UNSUPPORTED
        elif size not in (1, 2, 4, 8):
            flags |= F_HIDDEN_RET_PTR
            base_slot = 1

    raw_params = fn.get("Params") or []
    if len(raw_params) + base_slot > MAX_PARAMS:
        return None

    params = []
    for i, p in enumerate(raw_params):
        cp = classify_param(md, p, enum_ids)
        cp.slot = base_slot + i
        if cp.kind == K_UNKNOWN:
            flags |= F_UNSUPPORTED
        params.append(cp)

    # aux_value indexes into the *parameter* list; the C++ side reads captured
    # values by parameter index too, so no slot translation is needed. Drop
    # references that point outside the list rather than trusting them at runtime.
    for cp in params:
        if cp.aux_kind in (AUX_BYTES_FROM_PARAM, AUX_COUNT_FROM_PARAM):
            if not (0 <= cp.aux_value < len(params)):
                cp.aux_kind, cp.aux_value = AUX_NONE, 0

    return params, flags


def collect_enums(md):
    """Index only the enums a parameter can actually reference (950 of 7005)."""
    referenced = {}

    def visit(t, depth=0):
        if depth > 16:
            return
        kind = t.get("Kind")
        if kind == "ApiRef":
            node, _ = md.resolve(t)
            if node.get("Kind") == "Enum":
                referenced.setdefault((t.get("Api"), t.get("Name")), node)
        elif kind in ("PointerTo", "LPArray"):
            visit(t["Child"], depth + 1)

    for api, fn in md.functions:
        for p in fn.get("Params") or []:
            visit(p["Type"])

    enums = []
    enum_ids = {}
    for (eapi, ename), node in sorted(referenced.items()):
        node = dict(node)
        node["__api__"] = eapi
        enum_ids[(eapi, ename)] = len(enums)
        enums.append((eapi, ename, node))
    return enums, enum_ids


def resolve_enum_index(md, t, enum_ids, depth=0):
    """The enum table index a param type ultimately refers to, or NO_ENUM.

    This deliberately recurses *through* PointerTo/LPArray, so a PULONG whose
    pointee is PAGE_PROTECTION_FLAGS gets that table too. The field therefore
    means "the enum reached by following this type", not "the enum this argument
    decodes to" -- a consumer has to check the parameter kind before deciding
    which value to hand decodeEnum. ttd/src/utils.cpp does; decoding the raw
    argument of a pointer parameter is how VirtualProtect's lpflOldProtect came
    to be reported as a thirteen-flag decomposition of a stack address.
    """
    if depth > 16:
        return NO_ENUM
    kind = t.get("Kind")
    if kind == "ApiRef":
        node, _ = md.resolve(t)
        if node.get("Kind") == "Enum":
            return enum_ids.get((t.get("Api"), t.get("Name")), NO_ENUM)
    elif kind in ("PointerTo", "LPArray"):
        return resolve_enum_index(md, t["Child"], enum_ids, depth + 1)
    return NO_ENUM


def build(api_dir, out_path):
    print(f"[+] loading {api_dir} ...")
    md = Metadata(api_dir)
    print(f"[+] {len(md.functions)} functions, {len(md.types)} types")

    enums, enum_ids = collect_enums(md)
    print(f"[+] {len(enums)} referenced enums")

    strtab = StringTable()

    # enum tables
    enum_recs = []
    enumval_recs = []
    for eapi, ename, node in enums:
        values = node.get("Values") or []
        val_off = len(enumval_recs)
        for v in values:
            enumval_recs.append((strtab.add(v["Name"]), int(v["Value"])))
        enum_recs.append((
            strtab.add(ename), val_off, len(values),
            1 if node.get("Flags") else 0, md.enum_width(node),
        ))

    # functions, keyed by bare export name (module is a weak hint only -- API sets
    # mean kernel32!CreateFileW surfaces as KERNELBASE!CreateFileW in a trace)
    func_recs = []
    param_recs = []
    seen_names = {}
    skipped_arch = 0
    unsupported = 0
    collisions = 0

    for api, fn in sorted(md.functions, key=lambda x: x[1]["Name"]):
        name = fn["Name"]
        built = build_function(md, api, fn, enum_ids)
        if built is None:
            skipped_arch += 1
            continue
        params, flags = built

        if name in seen_names:
            prior = seen_names[name]
            if prior != tuple((p.kind, p.slot) for p in params):
                collisions += 1
            continue
        seen_names[name] = tuple((p.kind, p.slot) for p in params)

        for i, p in enumerate(params):
            enum_idx = resolve_enum_index(md, fn["Params"][i]["Type"], enum_ids)
            param_recs.append((
                strtab.add(p.name), strtab.add(p.type_name), p.kind, p.attrs,
                p.slot, p.aux_kind, p.aux_value, enum_idx, p.pointee_size,
                # win32json cannot tell us an x86 footprint -- it records x64 sizes --
                # so leave it 0 and let abi.cpp infer one from the display type, which
                # is what it has always done. build-phnt-index.py fills this in.
                0,
            ))
        if flags & F_UNSUPPORTED:
            unsupported += 1
        func_recs.append((
            strtab.add(name), strtab.add(fn.get("DllImport") or ""),
            len(param_recs) - len(params), len(params), flags,
        ))

    print(f"[+] indexed {len(func_recs)} functions "
          f"({skipped_arch} not x64, {unsupported} flagged UNSUPPORTED, "
          f"{collisions} name collisions with differing shapes)")
    print(f"[+] {len(param_recs)} params, {len(enumval_recs)} enum values, "
          f"{len(strtab.buf)} bytes of strings")

    size = write_index(out_path, func_recs, param_recs, enum_recs, enumval_recs, strtab)
    out_path = Path(out_path)
    print(f"[+] wrote {out_path} ({size / 1024 / 1024:.2f} MB)")
    return 0


def main(argv):
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("api_dir", nargs="?", default=str(here / "win32json" / "api"),
                    help="path to win32json/api")
    ap.add_argument("-o", "--output", default=str(here / "ttd" / "data" / "win32-index.bin"),
                    help="output blob path")
    args = ap.parse_args(argv)
    return build(args.api_dir, args.output)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
