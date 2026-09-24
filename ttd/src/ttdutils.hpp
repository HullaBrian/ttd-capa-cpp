#ifndef TTDUITLS_HPP
#define TTDUITLS_HPP

#include <windows.h>
#include <iostream>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <string>
#include <variant>
#include <vector>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

#include "log.hpp"
#include "win32meta.hpp"

// The TTD engine reports its own failures through this; route them to the same sink as our
// diagnostics so an embedding host sees SDK errors too instead of losing them to stderr.
class ConsoleErrorReporting : public TTD::ErrorReporting {
public:
    void __fastcall VPrintError(char const* fmt, va_list args) override {
        char buf[2048];
        vsnprintf(buf, sizeof(buf), fmt, args);
        ttdcapa::log::err() << "[-] [TTD SDK] " << buf << "\n";
    }
};

namespace ttdcapa {
    struct ImportRecord {
        std::string dll;
        std::string name;
        TTD::GuestAddress va;
    };

    struct ExportRecord {
        std::string name;
        TTD::GuestAddress va;
    };

    struct SectionRecord {
        std::string name;
        TTD::GuestAddress va;
    };

    // One call argument: either an integer or a dereferenced string
    using ArgValue = std::variant<int64_t, std::string>;

    // One parameter decoded with the help of the Win32 metadata index. `name` and
    // `type` point into the index blob, which outlives every record, so they cost
    // nothing to copy. Enum values keep their index rather than their decoded flag
    // names so millions of in-memory calls stay cheap; names are resolved once at
    // report-write time.
    struct DecodedArg {
        const char* name = nullptr;
        const char* type = nullptr;
        win32meta::ArgKind kind = win32meta::ArgKind::Unknown;
        uint32_t enum_index = 0xFFFFFFFFu;
        uint64_t raw = 0;             // the register/stack value as captured
        uint64_t deref = 0;           // pointee, for PtrToInt and friends
        double fval = 0.0;            // for Float/Double params (read from XMM)
        std::string str;              // decoded string contents
        std::vector<uint8_t> bytes;   // bounded buffer preview
        bool has_str = false;
        bool has_deref = false;
        bool has_fval = false;
        bool is_out = false;
        bool from_return = false;     // contents were read at the return position
        bool str_truncated = false;   // `str` stopped short of its NUL terminator
    };

    // A dereference deferred until the call returns, so [Out] parameters can be
    // rendered filled in -- something only a time-travel trace makes easy.
    struct PendingOut {
        uint16_t param_index = 0;
        win32meta::ArgKind kind = win32meta::ArgKind::Unknown;
        uint64_t ptr = 0;
        uint16_t pointee_size = 0;
        win32meta::AuxKind aux_kind = win32meta::AuxKind::None;
        int32_t aux_value = 0;
        uint64_t in_cap = 0;  // caller-supplied upper bound on length, 0 if unknown
    };

    struct CallRecord {
        uint64_t tid = 0;            // TTD Thread ID
        uint64_t seq = 0;            // monotonic record order (consistent with timeline order)
        std::string position;        // TTD navigable position "Sequence:Steps" (hex), for WinDbg
        // Where the call returned, in the same form. Empty when it never did -- a call
        // still running at the end of the trace, or one the process died inside, which
        // is a real state and not the same as returning instantly. Together with
        // `position` it gives the call's interval, which is the only thing that
        // distinguishes a wrapper dispatching to a syscall from two adjacent
        // operations: an inner call is one whose position falls inside that interval
        // on the same thread.
        std::string return_position;
        std::wstring module;         // resolved owning module, e.g. "kernel32" (no extension)
        std::string api;             // resolved export name, e.g. "CreateFileA"
        // Where the call instruction landed, when that was not the export itself -- a stub, a
        // hooked export table's thunk, the CFG dispatcher -- and the export was reached from
        // there by a jump; 0 for a direct call. `position` is still the call instruction's.
        uint64_t via = 0;
        // The call went through a function pointer and landed on an export that only returns.
        // The linker shares such code between every function with the same body, exported or
        // not, so `api` may not be the function the caller meant.
        bool ambiguous = false;
        std::vector<ArgValue> args;      // flat view consumed by capa (ints and strings)
        std::vector<DecodedArg> params;  // rich view; only meaningful when `metadata` is set
        bool metadata = false;           // args came from a real signature, not the heuristic
        bool has_ret = false;
        uint64_t ret = 0;
    };

    struct ProcessRecord {
        uint64_t pid = 0;
        uint64_t ppid = 0;
        std::string name;
        std::vector<std::string> env_strings;
        std::vector<uint64_t> threads;         // TTD UniqueThreadIds
        std::vector<CallRecord> calls;
    };

    // A loaded module's address range plus the export name for each exported address,
    // used to resolve a CALL target to module.api.
    struct ModuleExports {
        std::string name;                                       // module name without extension, something like "kernel32"
        TTD::GuestAddress base;
        uint64_t size = 0;
        std::vector<std::pair<uint64_t, std::string>> exports;  // exported function VA -> export name
    };

    // One resolved call target: which module it belongs to, its export name, and the
    // bitness of that module. The bitness is per module rather than per trace because
    // a WoW64 process runs 32-bit and 64-bit code side by side, and it decides which
    // calling convention the call's arguments follow.
    struct ResolvedExport {
        std::wstring module;
        std::string api;
        bool is64 = true;
    };

    // Navigates all module load events, and returns a map of all function VAs along with their associated module and function name
    std::unordered_map<uint64_t, ResolvedExport> resolveTraceModuleExports(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor);

    // TTD memory read utility function
    size_t readMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, void* dest, unsigned __int64 size);

    // An address below the first 64 KiB is never a valid user-mode string pointer, and
    // treating one as such is how a flags DWORD ends up rendered as text. The readers
    // enforce this; the recovery pass checks it first so it does not pay for a trace
    // seek to re-read something that will be rejected on arrival.
    constexpr uint64_t kMinStringAddr = 0x10000;

    // Where a bounded memory read is answered from, and at what fidelity.
    //
    // The IThreadView handed to a call/return callback can only answer at ThreadLocal
    // fidelity -- IReplayEngine.h:1440, "this is the policy used when querying memory
    // from the IThreadView interface as provided to a callback" -- and ThreadLocal
    // "concentrates on the current position and current thread, possibly ignoring some
    // of the memory observed by other threads, along with memory observed by the current
    // thread in the past or future". So a heap buffer the caller filled long before the
    // call reads back as nothing at all, even though the trace holds it and a cursor at
    // any other policy returns it. That is not a limit of the recording; it is a limit of
    // where we are standing when we ask. A cursor can be asked at a stronger policy,
    // which is what the string-recovery pass does with the misses the sweep collects.
    //
    // Implicitly constructible from IThreadView const*, so every existing call site keeps
    // reading exactly as it did.
    struct MemorySource {
        MemorySource(TTD::Replay::IThreadView const* view) : thread(view) {}
        MemorySource(TTD::Replay::ICursorView const* view, TTD::Replay::QueryMemoryPolicy p)
            : cursor(view), policy(p) {}

        TTD::Replay::IThreadView const* thread = nullptr;
        TTD::Replay::ICursorView const* cursor = nullptr;
        TTD::Replay::QueryMemoryPolicy policy = TTD::Replay::QueryMemoryPolicy::Default;

        // One QueryMemoryBuffer against whichever view this is. Returns bytes filled.
        size_t query(uint64_t addr, void* dst, size_t size) const;
    };

    // Fill `dst` with up to `size` bytes of guest memory recorded at `addr`, crossing
    // recorded-range seams, and return how many bytes were actually filled. A single
    // QueryMemoryBuffer stops at the end of one contiguous recorded range, so anything
    // the guest touched in more than one piece reads short; this keeps asking until the
    // buffer is full or a query returns nothing. Prefer it to a bare QueryMemoryBuffer
    // anywhere a short read would be mistaken for the end of the data.
    size_t readRecordedRun(MemorySource const& src, uint64_t addr, void* dst, size_t size);

    // UTF-16 -> UTF-8, for the wide strings TTD and the PE headers hand back
    std::string convertWstringToString(const std::wstring& ws);

    // Loads the trace's index, building one if the engine could not. Returns whether an index
    // is loaded afterwards; false still leaves a usable engine, just a much slower one.
    //
    // `rebuild_unloadable_index` deletes an existing index file the engine cannot read (a stale
    // one from an older TTD, or a truncated one) before building. The SDK will not do that
    // unasked -- deleting a user's file has to be an explicit act -- so without it, a trace with
    // a bad .idx replays unindexed no matter how many times it is re-run. Every pass shares this
    // one implementation: they used to each carry their own, and the copies drifted.
    bool buildTraceIndex(TTD::Replay::UniqueReplayEngine& engine, bool rebuild_unloadable_index);

    // Initializes the TTD engine based off a given trace file (.run) path
    bool initializeTTDEngine(TTD::Replay::UniqueReplayEngine& engine, std::wstring trace_file_path,
                             bool rebuild_unloadable_index = false);

    // All three readers below take an optional `truncated` out-parameter, set when the
    // returned text stopped before its NUL terminator -- because the trace recorded no
    // further bytes, or because maxChars was reached. That distinction has to travel
    // with the string: a name cut to 'WakeAllC' is otherwise indistinguishable from a
    // genuine 8-character export, and the report would look complete while being wrong.

    // Attempts to interpret the memory at a certain address as a string. If not a string, will return null
    std::optional<std::string> tryReadString(MemorySource const& src, uint64_t addr,
                                             bool* truncated = nullptr);

    // Read a NUL-terminated string the metadata told us is really there. Unlike
    // tryReadString these do not guess: no minimum length, and the wide reader
    // converts real UTF-16 (not just its ASCII subset) to UTF-8. Returns nullopt
    // only when the memory is unreadable or the bytes aren't a plausible string.
    std::optional<std::string> readAnsiString(MemorySource const& src, uint64_t addr,
                                              size_t maxChars = 512, bool* truncated = nullptr);
    std::optional<std::string> readWideString(MemorySource const& src, uint64_t addr,
                                              size_t maxChars = 512, bool* truncated = nullptr);

    // Read exactly `count` characters, stopping early only at a NUL. The native API
    // carries text in counted descriptors -- UNICODE_STRING and ANSI_STRING hold a
    // byte length beside the buffer -- and those are not required to be terminated,
    // so scanning for a terminator would run off the end of the string and into
    // whatever follows it. `truncated` means the trace recorded fewer characters
    // than the descriptor claimed, not that a terminator was missing.
    std::optional<std::string> readAnsiChars(MemorySource const& src, uint64_t addr,
                                             size_t count, bool* truncated = nullptr);
    std::optional<std::string> readWideChars(MemorySource const& src, uint64_t addr,
                                             size_t count, bool* truncated = nullptr);

    // Attempts to capture an argument as a string. If it doesn't look like a valid string, this function will return the same argument value
    ArgValue captureCallArg(MemorySource const& src, uint64_t value);
}

#endif