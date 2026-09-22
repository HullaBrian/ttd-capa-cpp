"""
Flatten the phnt native-API headers into the same binary index format
build-win32-index.py produces, so ttdcapa-extract can decode ntdll calls.

win32json describes the documented Win32 surface and almost nothing of the native
one -- 89 of its 17,148 functions are imported from ntdll. In a real trace that gap
is most of the calls: 59% of the API calls in a Windows Media Player trace had no
prototype, and 344 of the distinct functions missing were ntdll exports. Without a
prototype the extractor grabs a fixed number of argument registers, and whatever
the previous call left in them is reported as an argument.

phnt (https://github.com/winsiderss/phnt, vendored as the `phnt` submodule, MIT) is
the native API header set maintained for System Informer; NtDoc is generated from
it. It declares 2,482 functions with SAL annotations that map directly onto fields
this index already carries -- direction, optionality, and the parameter holding a
buffer's length.

    python tools/build-phnt-index.py [phnt] [-o ttd/data/phnt-index.bin]

The output is merged *under* win32-index.bin at load time: a real win32json
signature always wins, and this only fills gaps. See win32meta.cpp.

Why a textual parser rather than libclang: SAL macros expand to nothing under a
normal preprocess, and the SAL is the most valuable part of the input. phnt's
declaration style is rigidly consistent, so ~100 lines of regex parse 2,492 of
2,492 declarations.
"""
import re
import sys
import argparse
import collections
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from indexformat import (
    MAX_PARAMS, NO_ENUM, StringTable, write_index,
    K_UNKNOWN, K_INTEGER, K_BOOL, K_HANDLE, K_FLOAT, K_DOUBLE,
    K_ANSI_STRING, K_WIDE_STRING, K_ANSI_BUFFER, K_WIDE_BUFFER, K_BYTE_BUFFER,
    K_PTR_TO_INT, K_STRUCT_PTR, K_FUNC_PTR, K_GUID, K_POINTER,
    K_PTR_TO_ANSI_STRING, K_PTR_TO_WIDE_STRING,
    K_COUNTED_ANSI_STRING, K_COUNTED_WIDE_STRING,
    A_IN, A_OUT, A_OPTIONAL, A_CONST, A_RESERVED,
    AUX_NONE, AUX_BYTES_FROM_PARAM, AUX_COUNT_FROM_PARAM,
    F_UNSUPPORTED,
)

# ---------------------------------------------------------------------------
# 1. lexing
# ---------------------------------------------------------------------------

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")

# A declaration is a storage-class macro, a return type, a calling convention, and
# a name followed by a parameter list. The bounded [\s\S]{0,200} keeps a stray
# NTSYSAPI in a comment-stripped macro from swallowing half a header.
DECL = re.compile(
    r"\b(?:NTSYSCALLAPI|NTSYSAPI|PHNTAPI)\b[\s\S]{0,200}?"
    r"\b(?:NTAPI|NTAPI_INLINE|WINAPI|__cdecl)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(")

# A leading SAL annotation: an underscore-prefixed token, optionally with a
# parenthesised argument list. Nothing in phnt's parameter *types* is spelled this
# way, which is what makes peeling them off by shape safe.
SAL_TOKEN = re.compile(r"^(_[A-Za-z0-9_]*_|__[a-z][A-Za-z0-9_]*)\s*")


def strip_comments(text):
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub(" ", text))


def match_paren(text, open_idx):
    """Index of the ')' matching the '(' at open_idx, or -1."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


def split_top(text):
    """Split on commas that are not inside parentheses."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        out.append("".join(cur))
    return [s.strip() for s in out if s.strip()]


def peel_sal(param_text):
    """(annotations, remaining declaration) for one parameter."""
    annots, s = [], param_text.strip()
    while True:
        m = SAL_TOKEN.match(s)
        if not m:
            return annots, s.strip()
        tok, rest = m.group(1), s[m.end():]
        if rest.startswith("("):
            close = match_paren(rest, 0)
            if close < 0:
                return annots, s.strip()
            annots.append((tok, split_top(rest[1:close])))
            s = rest[close + 1:]
        else:
            annots.append((tok, []))
            s = rest


# ---------------------------------------------------------------------------
# 2. the type graph, harvested from the headers themselves
# ---------------------------------------------------------------------------
#
# Resolving `PFOO` to `FOO*` by stripping a leading P is how you decide that
# PORT_MESSAGE is a pointer to ORT_MESSAGE. So the aliases are read out of phnt's
# own typedefs instead, which is exact wherever phnt defines the type.

FUNC_CLASS = re.compile(r"_Function_class_\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
FUNCPTR_TYPEDEF = re.compile(
    r"\btypedef\s+[^;{}]*?\(\s*(?:NTAPI|WINAPI|CALLBACK|__cdecl|STDMETHODCALLTYPE)?\s*"
    r"\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\(")
# typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
# typedef struct _TEB *PTEB;      typedef IO_APC_ROUTINE* PIO_APC_ROUTINE;
PTR_TYPEDEF = re.compile(
    r"\btypedef\s+(?:const\s+)?(?:struct\s+|union\s+|enum\s+)?"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\*+\s*(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*;")
# typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;
SIMPLE_TYPEDEF = re.compile(
    r"\btypedef\s+(?:const\s+)?([A-Za-z_][A-Za-z0-9_]*)\s+"
    r"((?:\*?\s*[A-Za-z_][A-Za-z0-9_]*\s*,\s*)*\*?\s*[A-Za-z_][A-Za-z0-9_]*)\s*;")
AGGREGATE = re.compile(r"\btypedef\s+(struct|union|enum)\b")


def match_brace(text, open_idx):
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


class TypeGraph:
    """What phnt's own typedefs say about each name."""

    def __init__(self):
        self.ptr_alias = {}   # PFOO -> FOO      (PFOO is FOO*)
        self.alias = {}       # BAR -> FOO       (typedef FOO BAR;)
        self.aggregates = {}  # FOO -> struct | union | enum
        self.functypes = set()   # a function type: FOO* is a code pointer
        self.funcptrs = set()    # already a pointer: typedef RET (NTAPI *FOO)(...)

    def harvest(self, text):
        for m in FUNC_CLASS.finditer(text):
            self.functypes.add(m.group(1))
        for m in FUNCPTR_TYPEDEF.finditer(text):
            self.funcptrs.add(m.group(1))

        # typedef struct|union|enum _X { ... } NAME, *PNAME;  -- brace-matched so a
        # nested anonymous struct cannot end the block early, and so the close tag is
        # attributed to the right keyword.
        for m in AGGREGATE.finditer(text):
            brace = text.find("{", m.end())
            semi = text.find(";", m.end())
            if brace < 0 or (semi != -1 and semi < brace):
                continue  # a forward declaration; PTR_TYPEDEF handles it
            close = match_brace(text, brace)
            if close < 0:
                continue
            end = text.find(";", close)
            if end < 0:
                continue
            self._record_names(m.group(1), text[close + 1:end])

        for m in PTR_TYPEDEF.finditer(text):
            src, dst = m.group(1), m.group(2)
            if src not in ("typedef", "const") and dst != src:
                self.ptr_alias.setdefault(dst, src.lstrip("_"))
        for m in SIMPLE_TYPEDEF.finditer(text):
            src = m.group(1)
            if src in ("struct", "union", "enum"):
                continue
            for name in m.group(2).split(","):
                name = name.strip()
                if name.startswith("*"):
                    self.ptr_alias.setdefault(name.lstrip("* "), src)
                elif name != src:
                    self.alias.setdefault(name, src)

    def _record_names(self, kind, names_text):
        names = [n.strip() for n in names_text.split(",") if n.strip()]
        base = next((n.split("[")[0].strip() for n in names if not n.startswith("*")), None)
        if not base or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", base):
            return
        self.aggregates.setdefault(base, kind)
        for n in names:
            if n.startswith("*"):
                ptr = n.lstrip("* ").strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", ptr) and ptr != base:
                    self.ptr_alias.setdefault(ptr, base)


# ---------------------------------------------------------------------------
# 3. type classification
# ---------------------------------------------------------------------------
#
# (kind, pointee_size, x86_footprint). An unmapped type degrades to an opaque
# pointer or an integer, never to a guess: a wrong ArgKind dereferences something
# that is not a pointer.

# Scalars passed by value: name -> (kind, byte width)
SCALARS = {
    "VOID": (K_INTEGER, 0), "void": (K_INTEGER, 0),
    "BOOLEAN": (K_BOOL, 1), "BOOL": (K_BOOL, 4), "LOGICAL": (K_BOOL, 4),
    "CHAR": (K_INTEGER, 1), "UCHAR": (K_INTEGER, 1), "BYTE": (K_INTEGER, 1),
    "CCHAR": (K_INTEGER, 1), "SBYTE": (K_INTEGER, 1),
    "SHORT": (K_INTEGER, 2), "USHORT": (K_INTEGER, 2), "WCHAR": (K_INTEGER, 2),
    "WORD": (K_INTEGER, 2), "LANGID": (K_INTEGER, 2), "CSHORT": (K_INTEGER, 2),
    "INT": (K_INTEGER, 4), "UINT": (K_INTEGER, 4), "LONG": (K_INTEGER, 4),
    "ULONG": (K_INTEGER, 4), "DWORD": (K_INTEGER, 4), "NTSTATUS": (K_INTEGER, 4),
    "ACCESS_MASK": (K_INTEGER, 4), "LCID": (K_INTEGER, 4), "HRESULT": (K_INTEGER, 4),
    "KPRIORITY": (K_INTEGER, 4), "LSTATUS": (K_INTEGER, 4), "SECURITY_INFORMATION": (K_INTEGER, 4),
    "COLORREF": (K_INTEGER, 4), "ATOM": (K_INTEGER, 2), "PS_PROTECTION": (K_INTEGER, 1),
    "LONG32": (K_INTEGER, 4), "ULONG32": (K_INTEGER, 4), "INT32": (K_INTEGER, 4),
    "UINT32": (K_INTEGER, 4), "NTSTATUS_HRESULT": (K_INTEGER, 4),
    "LONG64": (K_INTEGER, 8), "ULONG64": (K_INTEGER, 8), "INT64": (K_INTEGER, 8),
    "UINT64": (K_INTEGER, 8), "LONGLONG": (K_INTEGER, 8), "ULONGLONG": (K_INTEGER, 8),
    "DWORD64": (K_INTEGER, 8), "QWORD": (K_INTEGER, 8),
    "LARGE_INTEGER": (K_INTEGER, 8), "ULARGE_INTEGER": (K_INTEGER, 8),
    "FLOAT": (K_FLOAT, 4), "DOUBLE": (K_DOUBLE, 8), "float": (K_FLOAT, 4),
    "double": (K_DOUBLE, 8),
    "char": (K_INTEGER, 1), "wchar_t": (K_INTEGER, 2), "short": (K_INTEGER, 2),
    "int": (K_INTEGER, 4), "unsigned": (K_INTEGER, 4), "long": (K_INTEGER, 4),
}

# Pointer-sized integers: 8 bytes on x64, 4 on x86. Split out because the width is
# the whole reason the x86 footprint byte exists.
POINTER_SIZED_INTS = {
    "SIZE_T", "SSIZE_T", "ULONG_PTR", "LONG_PTR", "DWORD_PTR", "UINT_PTR",
    "INT_PTR", "HANDLE_PTR", "KAFFINITY", "ULONG_PTR32", "PVOID64",
    "size_t", "ptrdiff_t", "intptr_t", "uintptr_t",
    "LRESULT", "LPARAM", "WPARAM", "DLL_DIRECTORY_COOKIE",
}

# Opaque handles: pointer-sized, and never dereferenced.
HANDLES = {
    "HANDLE", "SAM_HANDLE", "LSA_HANDLE", "REGHANDLE", "HWND", "HDESK", "HWINSTA",
    "HMENU", "HDC", "HHOOK", "HICON", "HCURSOR", "HBRUSH", "HGDIOBJ", "HMONITOR",
    "HKL", "HRAWINPUT", "HACCEL", "HBITMAP", "HFONT", "HPALETTE", "HRGN", "HDWP",
    "HTOUCHINPUT", "HGESTUREINFO", "HKEY", "HMODULE", "HINSTANCE", "HGLOBAL",
    "HLOCAL", "HRSRC", "HFILE", "HTASK", "HWINEVENTHOOK", "HDEVINFO", "HIMC",
    "HUMPD", "HCOLORSPACE", "D3DKMT_HANDLE", "TP_POOL", "HPCON",
}

# Counted string descriptors. The single most valuable native type: 300-odd
# parameter occurrences across phnt, and the native equivalent of a PWSTR.
COUNTED_WIDE = {"UNICODE_STRING", "UNICODE_STRING32", "UNICODE_STRING64"}
COUNTED_ANSI = {"STRING", "ANSI_STRING", "OEM_STRING", "UTF8_STRING", "STRING32", "STRING64"}

# Character pointers, by the name of the type they point at.
WIDE_CHARS = {"WCHAR", "WCH", "OLECHAR", "TCHAR"}
ANSI_CHARS = {"CHAR", "CH", "UCHAR", "BYTE"}

# Pointer typedefs phnt does not define with a typedef we can harvest, or where
# the harvested answer is not what the decoder wants.
EXPLICIT_POINTERS = {
    "PVOID": ("VOID", 1), "LPVOID": ("VOID", 1), "PVOID64": ("VOID", 1),
    "PCVOID": ("VOID", 1), "LPCVOID": ("VOID", 1),
    "PSTR": ("CHAR", 1), "PCSTR": ("CHAR", 1), "LPSTR": ("CHAR", 1), "LPCSTR": ("CHAR", 1),
    "PCH": ("CHAR", 1), "PCCH": ("CHAR", 1), "PCHAR": ("CHAR", 1), "PCUCHAR": ("UCHAR", 1),
    "PWSTR": ("WCHAR", 1), "PCWSTR": ("WCHAR", 1), "LPWSTR": ("WCHAR", 1),
    "LPCWSTR": ("WCHAR", 1), "PWCH": ("WCHAR", 1), "PCWCH": ("WCHAR", 1),
    "PWCHAR": ("WCHAR", 1), "PCWCHAR": ("WCHAR", 1), "LPCWCH": ("WCHAR", 1),
    "PUCHAR": ("UCHAR", 1), "PBYTE": ("BYTE", 1), "LPBYTE": ("BYTE", 1),
    "PBOOLEAN": ("BOOLEAN", 1), "PBOOL": ("BOOL", 1), "PLOGICAL": ("LOGICAL", 1),
    "PSHORT": ("SHORT", 1), "PUSHORT": ("USHORT", 1), "PWORD": ("WORD", 1),
    "PLONG": ("LONG", 1), "PULONG": ("ULONG", 1), "PDWORD": ("DWORD", 1),
    "LPDWORD": ("DWORD", 1), "PINT": ("INT", 1), "PUINT": ("UINT", 1),
    "PNTSTATUS": ("NTSTATUS", 1), "PACCESS_MASK": ("ACCESS_MASK", 1),
    "PLONG64": ("LONG64", 1), "PULONG64": ("ULONG64", 1),
    "PLONGLONG": ("LONGLONG", 1), "PULONGLONG": ("ULONGLONG", 1),
    "PLARGE_INTEGER": ("LARGE_INTEGER", 1), "PULARGE_INTEGER": ("ULARGE_INTEGER", 1),
    "PSIZE_T": ("SIZE_T", 1), "PSSIZE_T": ("SSIZE_T", 1),
    "PULONG_PTR": ("ULONG_PTR", 1), "PLONG_PTR": ("LONG_PTR", 1),
    "PDWORD_PTR": ("DWORD_PTR", 1), "PUINT_PTR": ("UINT_PTR", 1),
    "PHANDLE": ("HANDLE", 1), "PSAM_HANDLE": ("SAM_HANDLE", 1),
    "PLSA_HANDLE": ("LSA_HANDLE", 1), "PREGHANDLE": ("REGHANDLE", 1),
    "PGUID": ("GUID", 1), "LPGUID": ("GUID", 1), "LPCGUID": ("GUID", 1),
    "PCGUID": ("GUID", 1), "REFGUID": ("GUID", 1), "REFIID": ("GUID", 1),
    "REFCLSID": ("GUID", 1), "PIID": ("GUID", 1), "PCLSID": ("GUID", 1),
    "PUNICODE_STRING": ("UNICODE_STRING", 1), "PCUNICODE_STRING": ("UNICODE_STRING", 1),
    "PSTRING": ("STRING", 1), "PCSTRING": ("STRING", 1),
    "PANSI_STRING": ("ANSI_STRING", 1), "PCANSI_STRING": ("ANSI_STRING", 1),
    "POEM_STRING": ("OEM_STRING", 1), "PCOEM_STRING": ("OEM_STRING", 1),
    "PUTF8_STRING": ("UTF8_STRING", 1), "PCUTF8_STRING": ("UTF8_STRING", 1),
    # security descriptors and SIDs are opaque blobs, not structs we expand
    "PSID": ("VOID", 1), "PSECURITY_DESCRIPTOR": ("VOID", 1),
    "PISID": ("VOID", 1), "PSID_AND_ATTRIBUTES": ("VOID", 1),
}

# The by-value aggregates that turn up in native signatures, with the sizes the
# headers do not state textually. Anything not here and not a scalar decodes as
# Unknown rather than being guessed at.
BY_VALUE_SIZE = {
    "POINT": 8, "SIZE": 8, "RECT": 16, "LUID": 8, "GUID": 16,
    "UNICODE_STRING": 16, "ANSI_STRING": 16, "STRING": 16, "OEM_STRING": 16,
    "M128A": 16, "FLOAT128": 16, "PROCESSOR_NUMBER": 4, "GROUP_AFFINITY": 16,
    "WNF_STATE_NAME": 8, "WNF_TYPE_ID": 16, "OBJECT_ATTRIBUTES": 48,
    "IO_STATUS_BLOCK": 16, "CLIENT_ID": 16, "RTL_BITMAP": 16,
    "FILETIME": 8, "KSYSTEM_TIME": 12,
}

# A name that is spelled like a Windows pointer typedef. Only consulted after every
# other rule has failed, and only to choose "opaque pointer" over "no idea".
PTR_NAME = re.compile(r"^(?:P|LP|PC|LPC)[A-Z][A-Z0-9_]*$")

# A by-value name that phnt does not define, spelled the way the Windows SDK spells
# an enum -- SECURITY_IMPERSONATION_LEVEL, JOBOBJECTINFOCLASS, KTMOBJECT_TYPE. They
# come from headers phnt includes rather than defines, so there is nothing to
# harvest, and every one of them is a 4-byte enum. Guessing the width is safe in a
# way that guessing a *kind* is not: the parameter stays one x64 slot either way.
ENUM_NAME = re.compile(
    r"^[A-Z][A-Z0-9_]*(?:INFOCLASS|_CLASS|_LEVEL|_TYPE|_STATE|_MASK|_SOURCE|_KIND|"
    r"_MODE|_ACTION|_FORMAT|_CONTROL|_SIGNING_LEVEL)$")

# Types that are a pointer in disguise and have no useful pointee.
OPAQUE_BY_VALUE = {"va_list", "PVOID32"}

# Callback typedefs the Windows SDK defines and phnt merely uses, so there is no
# typedef here to harvest. All of them are already pointers.
SDK_CALLBACKS = {
    "MONITORENUMPROC", "TIMERPROC", "HOOKPROC", "WNDPROC", "DLGPROC",
    "WNDENUMPROC", "SENDASYNCPROC", "NOTIFICATIONCALLBACK", "PROPENUMPROCEXW",
    "EDITWORDBREAKPROCW", "WINEVENTPROC", "DRAWSTATEPROC",
}

# `_In_reads_bytes_(X)`-style annotations, and whether the count is bytes.
SIZE_SAL_BYTES = {
    "_In_reads_bytes_", "_In_reads_bytes_opt_", "_Out_writes_bytes_",
    "_Out_writes_bytes_opt_", "_Out_writes_bytes_to_", "_Out_writes_bytes_to_opt_",
    "_Out_writes_bytes_all_", "_Out_writes_bytes_all_opt_", "_Inout_updates_bytes_",
    "_Inout_updates_bytes_opt_", "_Inout_updates_bytes_to_",
    "_Inout_updates_bytes_to_opt_", "_In_reads_bytes_to_", "_In_reads_bytes_to_opt_",
    "_Field_size_bytes_",
}
SIZE_SAL_ELEMS = {
    "_In_reads_", "_In_reads_opt_", "_Out_writes_", "_Out_writes_opt_",
    "_Out_writes_to_", "_Out_writes_to_opt_", "_Out_writes_all_",
    "_Out_writes_all_opt_", "_Inout_updates_", "_Inout_updates_opt_",
    "_Inout_updates_to_", "_Inout_updates_to_opt_", "_In_reads_to_ptr_",
}

def direction_of(tok):
    """Direction and optionality bits for one SAL annotation.

    Derived from the name rather than tabulated, because the sized-buffer forms
    carry direction too and there are dozens of them: `_Out_writes_bytes_to_opt_`
    is an optional out-parameter as much as `_Out_opt_` is. Tabulating only the
    bare forms is how NtQueryInformationProcess ends up with an [In] buffer, which
    then never gets re-read at the return where the callee actually filled it in.
    """
    attrs = 0
    if tok.startswith("_In_") or tok == "_In_":
        attrs |= A_IN
    if tok.startswith("_Out") or tok.startswith("_Deref_out"):
        attrs |= A_OUT
    if tok.startswith("_Inout_"):
        attrs |= A_IN | A_OUT
    if tok.startswith("_Reserved_"):
        attrs |= A_IN | A_RESERVED
    if attrs and ("_opt_" in tok or tok.endswith("_opt_")):
        attrs |= A_OPTIONAL
    return attrs


def normalize(decl_type):
    """('BASE', pointer_depth) with qualifiers dropped."""
    toks = [t for t in decl_type.replace("*", " * ").split()
            if t not in ("const", "CONST", "volatile", "struct", "union", "enum", "_In_")]
    depth = sum(1 for t in toks if t == "*")
    names = [t for t in toks if t != "*"]
    return (names[-1] if names else ""), depth


class Classifier:
    def __init__(self, graph):
        self.graph = graph
        self.unmapped = collections.Counter()     # no rule at all: decodes as Unknown
        self.unresolved = collections.Counter()   # pointer to something we cannot name

    def resolve(self, base, depth):
        """Follow pointer typedefs and aliases until `base` is a real type."""
        for _ in range(8):
            if base in SCALARS or base in POINTER_SIZED_INTS or base in HANDLES:
                return base, depth
            if base in COUNTED_WIDE or base in COUNTED_ANSI:
                return base, depth
            if base in EXPLICIT_POINTERS:
                base, add = EXPLICIT_POINTERS[base]
                depth += add
                continue
            if base in self.graph.funcptrs or base in self.graph.functypes:
                return base, depth
            if base in self.graph.aggregates:
                return base, depth
            if base in self.graph.ptr_alias:
                base = self.graph.ptr_alias[base]
                depth += 1
                continue
            if base in self.graph.alias:
                base = self.graph.alias[base]
                continue
            return base, depth
        return base, depth

    def classify(self, decl_type):
        """(kind, pointee_size, x86_footprint, display_name)."""
        raw_base, raw_depth = normalize(decl_type)
        base, depth = self.resolve(raw_base, raw_depth)

        if depth == 0:
            return self._by_value(base, raw_base)
        display = self._display(base, depth)
        if depth >= 2:
            # T** -- surface the inner pointer, and the string case besides
            if base in WIDE_CHARS:
                return K_PTR_TO_WIDE_STRING, 8, 4, display
            if base in ANSI_CHARS:
                return K_PTR_TO_ANSI_STRING, 8, 4, display
            return K_PTR_TO_INT, 8, 4, display
        return self._by_pointer(base, display)

    def _display(self, base, depth):
        # Always spelled with explicit stars. abi.cpp reads a struct parameter's
        # display name to tell a pointer from an aggregate pushed by value on x86,
        # and "POBJECT_ATTRIBUTES" would read as the latter.
        return base + "*" * depth

    def _by_value(self, base, raw_base):
        if base in HANDLES:
            return K_HANDLE, 8, 4, raw_base
        if base in POINTER_SIZED_INTS:
            return K_INTEGER, 8, 4, raw_base
        if base in SCALARS:
            kind, width = SCALARS[base]
            foot = 8 if width == 8 else 4
            return kind, width, foot, raw_base
        if base in self.graph.funcptrs or base in SDK_CALLBACKS:
            return K_FUNC_PTR, 8, 4, raw_base
        if self.graph.aggregates.get(base) == "enum":
            # An enum is an int. Which int is a separate question -- phnt types flag
            # arguments as plain ULONG, so there is no table to name here.
            return K_INTEGER, 4, 4, raw_base
        if base in BY_VALUE_SIZE:
            size = BY_VALUE_SIZE[base]
            if size in (1, 2, 4, 8):
                return K_INTEGER, size, 8 if size == 8 else 4, raw_base
            # x64 passes a larger aggregate by hidden pointer; x86 pushes it whole,
            # and we know how wide it is, so both ABIs lay out.
            return K_STRUCT_PTR, size, (size + 3) // 4 * 4, raw_base
        if base in self.graph.aggregates:
            # A by-value aggregate whose size the headers do not state. It still
            # occupies exactly one x64 slot either way -- in a register if it is
            # 1/2/4/8 bytes, by hidden pointer otherwise -- so the parameters after
            # it stay correctly placed and only this one reads as unknown. x86
            # genuinely cannot be laid out, which the zero footprint says.
            self.unmapped[base] += 1
            return K_UNKNOWN, 0, 0, raw_base
        if base in OPAQUE_BY_VALUE or PTR_NAME.match(base):
            # An unresolved name spelled like a Windows pointer typedef (PACL,
            # PCONTEXT, PLUID). phnt does not define these -- they come from the SDK
            # headers -- and an opaque pointer is both safe and almost certainly
            # right. Anything else unknown stays unknown rather than being guessed.
            return K_POINTER, 0, 4, raw_base
        if ENUM_NAME.match(base):
            return K_INTEGER, 4, 4, raw_base
        self.unmapped[base] += 1
        return K_UNKNOWN, 0, 0, raw_base

    def _by_pointer(self, base, display):
        if base in COUNTED_WIDE:
            return K_COUNTED_WIDE_STRING, 16, 4, display
        if base in COUNTED_ANSI:
            return K_COUNTED_ANSI_STRING, 16, 4, display
        if base in WIDE_CHARS:
            return K_WIDE_STRING, 2, 4, display
        if base in ANSI_CHARS:
            return K_ANSI_STRING, 1, 4, display
        if base in self.graph.funcptrs or base in self.graph.functypes:
            return K_FUNC_PTR, 8, 4, display
        if base in ("VOID", "void"):
            return K_POINTER, 0, 4, display
        if base == "GUID":
            return K_GUID, 16, 4, display
        if base in HANDLES:
            return K_PTR_TO_INT, 8, 4, display
        if base in POINTER_SIZED_INTS:
            return K_PTR_TO_INT, 8, 4, display
        if base in SCALARS:
            _kind, width = SCALARS[base]
            return K_PTR_TO_INT, width or 8, 4, display
        if base in self.graph.aggregates:
            return K_STRUCT_PTR, BY_VALUE_SIZE.get(base, 0), 4, display
        # Unknown pointee: an opaque pointer is always safe, and the untyped-string
        # heuristic in abi.cpp still gets a crack at it.
        self.unresolved[base] += 1
        return K_POINTER, 0, 4, display


# ---------------------------------------------------------------------------
# 4. parsing declarations into parameters
# ---------------------------------------------------------------------------

class Param:
    __slots__ = ("name", "type_name", "kind", "attrs", "slot", "aux_kind",
                 "aux_value", "aux_expr", "pointee_size", "x86_footprint")

    def __init__(self):
        self.name = ""
        self.type_name = ""
        self.kind = K_UNKNOWN
        self.attrs = 0
        self.slot = 0
        self.aux_kind = AUX_NONE
        self.aux_value = 0
        self.aux_expr = None
        self.pointee_size = 0
        self.x86_footprint = 0


def parse_param(text, classifier):
    """One parameter, or None if it cannot be understood."""
    annots, decl = peel_sal(text)
    if decl in ("...", ""):
        return None

    p = Param()
    for tok, args in annots:
        p.attrs |= direction_of(tok)
        if tok in SIZE_SAL_BYTES and args:
            p.aux_kind, p.aux_expr = AUX_BYTES_FROM_PARAM, args[0]
        elif tok in SIZE_SAL_ELEMS and args:
            p.aux_kind, p.aux_expr = AUX_COUNT_FROM_PARAM, args[0]
    if "const" in decl.split() or "CONST" in decl.split():
        p.attrs |= A_CONST
    if not p.attrs & (A_IN | A_OUT):
        p.attrs |= A_IN  # unannotated parameters are inbound in practice

    # `TYPE Name`, `TYPE *Name`, `TYPE Name[]`, or -- for an unnamed parameter --
    # just `TYPE`. An array parameter is a pointer, so its brackets become a star
    # rather than being dropped; leaving them in would make the *name* look like
    # part of the type.
    array_depth = decl.count("[")
    decl = re.sub(r"\[[^\]]*\]", "", decl)
    toks = (decl.replace("*", " * ") + " * " * array_depth).split()
    tail = toks[-1] if toks else ""
    if len(toks) >= 2 and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tail):
        p.name = tail
        type_text = " ".join(toks[:-1])
    else:
        p.name = ""
        type_text = " ".join(toks)

    p.kind, p.pointee_size, p.x86_footprint, p.type_name = classifier.classify(type_text)
    return p


def resolve_aux(params):
    """Turn a SAL size expression into the index of the parameter holding it."""
    by_name = {p.name: i for i, p in enumerate(params) if p.name}
    for p in params:
        if p.aux_kind == AUX_NONE:
            continue
        expr = (p.aux_expr or "").strip().lstrip("*").strip()
        idx = by_name.get(expr)
        if idx is None:
            # A computed size (`Length / sizeof(WCHAR)`, `*ReturnLength`) we cannot
            # attribute to one parameter. Drop it rather than point at the wrong one.
            p.aux_kind, p.aux_value = AUX_NONE, 0
            continue
        p.aux_value = idx
        # A sized buffer really is a buffer, whatever the pointee said.
        if p.kind in (K_POINTER, K_UNKNOWN, K_STRUCT_PTR, K_PTR_TO_INT):
            if p.kind == K_PTR_TO_INT and p.pointee_size in (1, 2):
                p.kind = K_ANSI_BUFFER if p.pointee_size == 1 else K_WIDE_BUFFER
            else:
                p.kind = K_BYTE_BUFFER
                p.pointee_size = 1
        elif p.kind == K_WIDE_STRING:
            p.kind = K_WIDE_BUFFER
        elif p.kind == K_ANSI_STRING:
            p.kind = K_ANSI_BUFFER


def parse_headers(phnt_dir):
    """{name: (params, flags)} for every declaration phnt makes."""
    paths = sorted(Path(phnt_dir).glob("*.h"))
    if not paths:
        raise SystemExit(f"no headers in {phnt_dir} (is the phnt submodule checked out?)")

    texts = {p.name: strip_comments(p.read_text(encoding="utf-8", errors="replace"))
             for p in paths}

    graph = TypeGraph()
    for text in texts.values():
        graph.harvest(text)
    classifier = Classifier(graph)

    functions = {}
    stats = collections.Counter()
    for text in texts.values():
        for m in DECL.finditer(text):
            name = m.group(1)
            open_idx = m.end() - 1
            close_idx = match_paren(text, open_idx)
            if close_idx < 0 or not text[close_idx + 1:close_idx + 8].strip().startswith(";"):
                continue
            stats["declarations"] += 1
            if name in functions:
                stats["duplicate"] += 1
                continue

            body = text[open_idx + 1:close_idx].strip()
            flags = 0
            params = []
            if body not in ("", "VOID", "void"):
                for raw in split_top(body):
                    if raw.strip() == "...":
                        flags |= F_UNSUPPORTED  # varargs have no fixed layout
                        continue
                    p = parse_param(raw, classifier)
                    if p is None:
                        flags |= F_UNSUPPORTED
                        continue
                    params.append(p)
            if len(params) > MAX_PARAMS:
                stats["too many params"] += 1
                continue
            resolve_aux(params)
            for i, p in enumerate(params):
                p.slot = i  # nothing in phnt returns an aggregate needing a hidden pointer
                if p.kind == K_UNKNOWN:
                    # Deliberately not F_UNSUPPORTED. An unknown parameter still
                    # occupies exactly one x64 slot, so every other parameter is
                    # still read from the right place and only this one shows as a
                    # raw value -- far better than sending the whole call back to
                    # the four-register heuristic. Only varargs, which have no fixed
                    # layout at all, decline the signature.
                    stats["unknown params"] += 1
            if flags & F_UNSUPPORTED:
                stats["unsupported"] += 1
            functions[name] = (params, flags)
            stats["parsed"] += 1
    return functions, classifier, stats


# ---------------------------------------------------------------------------
# 5. emit
# ---------------------------------------------------------------------------

def build(phnt_dir, out_path, verbose=False):
    print(f"[+] loading {phnt_dir} ...")
    functions, classifier, stats = parse_headers(phnt_dir)
    print(f"[+] {stats['declarations']} declarations, {stats['parsed']} functions "
          f"({stats['duplicate']} duplicate names, {stats['unsupported']} flagged UNSUPPORTED)")

    strtab = StringTable()
    func_recs = []
    param_recs = []
    for name in sorted(functions):
        params, flags = functions[name]
        for p in params:
            param_recs.append((
                strtab.add(p.name), strtab.add(p.type_name), p.kind, p.attrs,
                p.slot, p.aux_kind, p.aux_value, NO_ENUM, p.pointee_size,
                p.x86_footprint,
            ))
        func_recs.append((
            strtab.add(name), strtab.add("ntdll.dll"),
            len(param_recs) - len(params), len(params), flags,
        ))

    # No enum tables: phnt types flag arguments as plain ULONG. The few that are
    # worth naming are overlaid in C++ against win32json tables -- see the enum
    # overlay in builtinsigs.cpp -- because that is where the tables already are.
    print(f"[+] {len(param_recs)} params, {len(strtab.buf)} bytes of strings")
    if classifier.unresolved:
        total = sum(classifier.unresolved.values())
        print(f"[+] {len(classifier.unresolved)} pointee types were not nameable "
              f"({total} parameters); those decode as opaque pointers")
    if classifier.unmapped:
        total = sum(classifier.unmapped.values())
        print(f"[!] {len(classifier.unmapped)} by-value type names had no rule "
              f"({total} parameters); those decode as Unknown")
        if verbose:
            for name, n in classifier.unmapped.most_common(40):
                print(f"      {n:5}  {name}")

    size = write_index(out_path, func_recs, param_recs, [], [], strtab)
    print(f"[+] wrote {out_path} ({size / 1024 / 1024:.2f} MB)")
    return 0


def main(argv):
    here = Path(__file__).resolve().parent.parent
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("phnt_dir", nargs="?", default=str(here / "phnt"),
                    help="path to the phnt headers")
    ap.add_argument("-o", "--output", default=str(here / "ttd" / "data" / "phnt-index.bin"),
                    help="output blob path")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="list the type names that fell through to the fallback")
    args = ap.parse_args(argv)
    return build(args.phnt_dir, args.output, args.verbose)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
