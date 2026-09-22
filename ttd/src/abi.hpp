#ifndef ABI_HPP
#define ABI_HPP

// The calling-convention decoders.
//
// The Win32 metadata gives us types and semantics; mapping those onto registers
// and stack slots is ours to write (WIN32JSON-TTD-INTEGRATION-NOTES.md section 3).
// That's this file: given a signature and a thread's register state at a CALL,
// produce one DecodedArg per real parameter -- no more, no less.
//
// Microsoft x64 in one paragraph: the first four parameters go in RCX/RDX/R8/R9,
// or XMM0-3 if they're floating point. Crucially the slot index is *shared* between
// the two register files, so a float in position 2 lives in XMM2, not XMM0.
// Parameters five and up sit at [RSP+0x28] onwards, above the 32-byte shadow space
// the caller must reserve. Aggregates that aren't exactly 1/2/4/8 bytes are passed
// by hidden pointer, and a function returning one takes an extra hidden first
// parameter -- the indexer pre-computes both, so `slot` here is always final.
//
// x86 is simpler and harder at once. Every parameter -- integers, pointers and
// floats alike -- is pushed on the stack, so there are no registers to read; but
// because it is a byte offset rather than a slot index, each parameter's position
// depends on the *sizes* of the ones before it. computeStackOffsets() recovers
// those offsets from the signature. Note that __stdcall and __cdecl differ only in
// who pops the arguments, which is invisible from the callee's entry, so one layout
// serves both -- and that covers essentially the whole Win32 surface.
//
// A WoW64 trace holds 32-bit and 64-bit code at the same time, so the choice is
// made per call, from the bitness of the module owning the call target.

#include <cstdint>
#include <vector>

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>

#include "ttdutils.hpp"
#include "win32meta.hpp"

namespace ttdcapa {

    struct DecodeOptions {
        size_t max_buffer = 256;   // bytes of any one counted buffer to keep
        size_t max_string = 512;   // characters of any one string to keep
    };

    enum class GuestArch : uint8_t {
        X64,
        X86,
    };

    // A call's argument-passing state, whichever architecture it belongs to. Exactly
    // one of the context pointers is set, matching `arch`.
    struct CallFrame {
        GuestArch arch = GuestArch::X64;
        const AMD64_CONTEXT* x64 = nullptr;
        const X86_NT5_CONTEXT* x86 = nullptr;
        TTD::Replay::IThreadView const* thread = nullptr;

        uint16_t pointerSize() const { return arch == GuestArch::X64 ? 8 : 4; }
    };

    // True for the kinds that are a pointer in the guest, whatever they point at.
    // The report writer needs this to tell a parameter that *is* a value from one
    // that merely points at it -- decoding a pointer as though it were the value is
    // how a stack address comes out as a list of thirteen page-protection flags.
    bool isPointerKind(win32meta::ArgKind kind);

    // Decode every parameter of `sig` from the argument state at the call.
    // Dereferences that only make sense once the callee has run are appended to
    // `deferred` instead; feed those to resolvePendingOuts at the return.
    //
    // Returns false when this signature cannot be laid out for `frame.arch` -- see
    // computeStackOffsets -- which is the caller's cue to fall back to the heuristic
    // capture rather than report parameters read from the wrong offsets.
    bool decodeArgs(const win32meta::FuncSig& sig,
                    const CallFrame& frame,
                    const DecodeOptions& opt,
                    std::vector<DecodedArg>& out,
                    std::vector<PendingOut>& deferred);

    // Re-read the deferred dereferences at the return position and patch them into
    // `args` (which must be the vector decodeArgs filled in for this same call).
    void resolvePendingOuts(const std::vector<PendingOut>& pending,
                            const CallFrame& frame,
                            const DecodeOptions& opt,
                            std::vector<DecodedArg>& args);

    // True for the two NUL-terminated string kinds, which are what the sweep's
    // ThreadLocal view most often cannot see and what the recovery pass re-reads.
    bool isPlainStringKind(win32meta::ArgKind kind);

    // Re-read one string parameter's contents from `src` and store anything recovered in
    // `arg`. Returns true when `arg` gained a string.
    //
    // Rejects an empty result rather than recording one: a Globally* policy answers
    // "mapped but not recorded here" with a zero fill rather than a short read, and for
    // a string that arrives as a NUL in byte zero. An empty string is therefore never
    // evidence, only the absence of it.
    //
    // `accept_truncated` false also rejects a string that stopped before its terminator.
    // The free read at a call's return sets it: a thread view only knows the bytes its
    // thread touched, and a comparison stops at the first character that differs, so
    // `_wcsicmp` against 'IEXPLORE.EXE' offers 'IEXP' and nothing more. Declining that
    // leaves the parameter unread for the cursor pass, which is not held to one thread's
    // reading and returns the whole name. Taking the prefix instead would look like
    // progress while producing a value capa deliberately refuses to match on.
    bool recoverString(MemorySource const& src, const DecodeOptions& opt, DecodedArg& arg,
                       bool accept_truncated = true);

    // Byte offset of each parameter from the first argument on the x86 stack, in
    // parameter order. False when the signature has no knowable x86 layout, which is
    // exactly when decodeArgs would decline it. Exposed so --dump-sig can show the
    // layout without needing a trace to replay.
    bool x86StackLayout(const win32meta::FuncSig& sig, std::vector<uint16_t>& offsets);

    // Flatten decoded parameters into the int/string list capa matches rules
    // against. Strings recovered from [Out] parameters are included -- they are
    // genuine new evidence; symbolic enum names are not, so rules that match flags
    // numerically keep working.
    std::vector<ArgValue> toCapaArgs(const std::vector<DecodedArg>& args);

}  // namespace ttdcapa

#endif
