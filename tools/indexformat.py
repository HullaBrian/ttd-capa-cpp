"""
The on-disk shape of the API metadata index, shared by every builder that writes one.

There are two builders now -- `build-win32-index.py` over win32json for the documented
Win32 surface, and `build-phnt-index.py` over phnt for the native one -- and the C++
loader reads both with the same code. That only stays true if the record layouts stay
identical, which is what this module is for: the constants and the writer live in one
place rather than being kept in step by hand across two scripts.

Keep the K_* / A_* / AUX_* / F_* values in sync with `ttd/src/win32meta.hpp`.
"""
import io
import struct
from pathlib import Path

MAGIC = b"W32IDX01"
FORMAT_VERSION = 1

# --- decode kinds; keep in sync with ArgKind in ttd/src/win32meta.hpp ----------
K_UNKNOWN = 0
K_INTEGER = 1
K_BOOL = 2
K_HANDLE = 3
K_ENUM = 4
K_FLOAT = 5
K_DOUBLE = 6
K_ANSI_STRING = 7
K_WIDE_STRING = 8
K_ANSI_BUFFER = 9
K_WIDE_BUFFER = 10
K_BYTE_BUFFER = 11
K_PTR_TO_INT = 12
K_STRUCT_PTR = 13
K_FUNC_PTR = 14
K_GUID = 15
K_POINTER = 16
K_PTR_TO_ANSI_STRING = 17
K_PTR_TO_WIDE_STRING = 18
K_COUNTED_ANSI_STRING = 19   # ANSI_STRING* / STRING* / OEM_STRING*
K_COUNTED_WIDE_STRING = 20   # UNICODE_STRING*

# --- parameter attribute bits; keep in sync with ParamAttr in win32meta.hpp ---
A_IN = 0x01
A_OUT = 0x02
A_OPTIONAL = 0x04
A_CONST = 0x08
A_RESERVED = 0x10
A_NOT_NUL_TERM = 0x20
A_NULNUL_TERM = 0x40
A_COM_OUT_PTR = 0x80

# --- how a buffer's length is determined; keep in sync with AuxKind -----------
AUX_NONE = 0
AUX_BYTES_FROM_PARAM = 1
AUX_COUNT_FROM_PARAM = 2
AUX_COUNT_CONST = 3

# --- function flags; keep in sync with FuncFlag ------------------------------
F_HIDDEN_RET_PTR = 0x01
F_UNSUPPORTED = 0x02
F_SET_LAST_ERROR = 0x04

NO_ENUM = 0xFFFFFFFF

MAX_PARAMS = 255  # param_count is a u8; nothing real comes close (max observed: 18)


class StringTable:
    """Deduplicating NUL-terminated string pool. Offset 0 is always ""."""

    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.offsets = {"": 0}

    def add(self, s):
        if s is None:
            s = ""
        off = self.offsets.get(s)
        if off is None:
            off = len(self.buf)
            self.buf += s.encode("utf-8") + b"\x00"
            self.offsets[s] = off
        return off


def write_index(out_path, func_recs, param_recs, enum_recs, enumval_recs, strtab):
    """Serialize one index blob.

    Records are plain tuples in declaration order:
      func     (name_off, dll_off, first_param, param_count, flags)
      param    (name_off, type_off, kind, attrs, slot, aux_kind, aux_value,
                enum_idx, pointee_size, x86_footprint)
      enum     (name_off, first_value, value_count, is_flags, width)
      enumval  (name_off, value)

    `x86_footprint` is the number of bytes the parameter occupies on a 32-bit
    argument stack, or 0 for "work it out from the type". It lives in what used to be
    a pad byte, so a builder that leaves it 0 -- as build-win32-index.py does -- gets
    exactly the behaviour it had before. It exists because an 8-byte scalar is
    ambiguous on its own: Int64 really does push 8 bytes on x86, UIntPtr pushes 4,
    and guessing wrong silently shifts every later parameter.
    """
    blob = io.BytesIO()
    blob.write(MAGIC)
    blob.write(struct.pack(
        "<IIIIII", FORMAT_VERSION, len(func_recs), len(param_recs),
        len(enum_recs), len(enumval_recs), len(strtab.buf),
    ))
    for name_off, dll_off, param_off, count, flags in func_recs:
        blob.write(struct.pack("<IIIBBH", name_off, dll_off, param_off, count, flags, 0))
    for rec in param_recs:
        (name_off, type_off, kind, attrs, slot, aux_kind, aux_value, enum_idx,
         pointee, x86_footprint) = rec
        blob.write(struct.pack("<IIBBBBiIHB1x", name_off, type_off, kind, attrs,
                               slot, aux_kind, aux_value, enum_idx,
                               min(pointee, 0xFFFF), min(x86_footprint, 0xFF)))
    for name_off, val_off, val_count, is_flags, width in enum_recs:
        blob.write(struct.pack("<IIIBB2x", name_off, val_off, val_count, is_flags, width))
    for name_off, value in enumval_recs:
        blob.write(struct.pack("<I4xq", name_off, value))
    blob.write(strtab.buf)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(blob.getvalue())
    return out_path.stat().st_size
