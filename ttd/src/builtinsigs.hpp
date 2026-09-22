#ifndef BUILTINSIGS_HPP
#define BUILTINSIGS_HPP

// The three small hand-written tables, and why each one has to be hand-written.
//
// Most signatures are generated: win32json for the documented Win32 surface
// (build-win32-index.py) and phnt for the native one (build-phnt-index.py). Between
// them they cover everything that has a public source. What is left is:
//
//   1. win32u -- the win32k syscall stubs. phnt's ntuser.h has 292 of them but not
//      NtUserGetAsyncKeyState, which is the single most-called unsignatured function
//      in a desktop trace by an order of magnitude. Syscall-table projects publish
//      numbers and names, not prototypes, so there is nothing to generate from.
//
//   2. The C runtime -- memset, strlen, malloc and friends, exported by ntdll,
//      msvcrt and ucrtbase. Standard C, stable since 1989, and no metadata anywhere
//      describes them because nothing needs to.
//
//   3. The flag-enum overlay. phnt types every flag argument as a bare ULONG:
//      NtProtectVirtualMemory's NewProtection is a ULONG, not PAGE_PROTECTION_FLAGS.
//      win32json already holds those enum tables, so this names one for a given
//      function and parameter and the two halves of the index are stitched together.
//      It is a judgement about meaning rather than a fact any header states, which is
//      exactly why it cannot be generated.
//
// Keep all three short. Every row is a maintenance liability, and a wrong prototype
// is worse than no prototype -- it turns "we do not know" into a confident-looking
// value, which is the failure mode this whole subsystem exists to avoid.

#include <cstdint>
#include <span>

#include "win32meta.hpp"

namespace ttdcapa::win32meta {

    // One parameter of a hand-written signature. Deliberately not ParamSig: the slot
    // is implied by position, and there is no enum index because the overlay below
    // names its enums instead of numbering them.
    struct BuiltinParam {
        const char* name = "";
        const char* type = "";
        ArgKind kind = ArgKind::Unknown;
        uint8_t attrs = 0;
        uint16_t pointeeSize = 0;
        uint8_t x86Footprint = 4;
        AuxKind auxKind = AuxKind::None;
        int32_t auxValue = 0;
    };

    struct BuiltinFunc {
        const char* name = "";
        const char* dll = "";
        const BuiltinParam* params = nullptr;
        uint8_t paramCount = 0;
    };

    // Names a win32json enum table for one parameter of one function.
    struct EnumOverlay {
        const char* function = "";
        const char* parameter = "";
        const char* enumName = "";
    };

    // Both tables are static storage, so their strings outlive any index.
    std::span<const BuiltinFunc> builtinSignatures();
    std::span<const EnumOverlay> builtinEnumOverlays();

}  // namespace ttdcapa::win32meta

#endif
