/*
 * ttdcapa.h -- the embedding API for ttd-capa.
 *
 * ttd-capa turns a Time Travel Debugging (.run) trace into capa-compatible evidence. It has
 * three passes, all of which are exposed here:
 *
 *   1. ttdcapa_extract_report   -- the dynamic pass. Sweeps the trace's call/return events
 *                                  and emits a TTD report JSON: every call to a resolved
 *                                  module export, with Win32-metadata-decoded arguments and
 *                                  a navigable TTD position (Sequence:Steps).
 *   2. ttdcapa_scan_code        -- the static pass, part one. Reconstructs the memory regions
 *                                  the program created at runtime (unpacked / JIT'd /
 *                                  injected code) at the moments code ran in them, writing a
 *                                  .bin per snapshot plus a manifest describing them.
 *   3. ttdcapa_trace_code_hits  -- the static pass, part two. Given the instruction addresses
 *                                  a static match landed on, replays the trace with execute
 *                                  watchpoints to find when each actually ran.
 *
 * Rule matching is *not* here: it belongs to capa-cpp, which consumes the report JSON from
 * (1) and the manifest plus dumps from (2). The intended shape of an integration is
 * therefore: call (1) and (2) in-process, hand their output to capa-cpp, feed the resulting
 * match records back into (3), and merge everything into whatever timeline the host builds.
 * docs/EMBEDDING.md walks through that flow.
 *
 * ABI notes
 * ---------
 *  - C linkage, __cdecl, no C++ types across the boundary, no exceptions escape.
 *  - Every options struct starts with `struct_size`; set it to sizeof(the struct you
 *    compiled against) so a newer library can tell which fields you actually filled in.
 *  - Strings handed back in ttdcapa_string are owned by the library: release them with
 *    ttdcapa_string_free, not free().
 *  - Paths are wide (UTF-16) because that is what the TTD engine takes; returned text is
 *    UTF-8.
 *  - One call analyses one trace and is not internally parallel. Calls are not thread-safe
 *    against each other: the diagnostics sink and the Win32 metadata index are process-wide.
 */
#ifndef TTDCAPA_H
#define TTDCAPA_H

#include <stddef.h>
#include <stdint.h>
#include <wchar.h>

#if defined(TTDCAPA_STATIC)
#  define TTDCAPA_API
#elif defined(TTDCAPA_EXPORTS)
#  define TTDCAPA_API __declspec(dllexport)
#else
#  define TTDCAPA_API __declspec(dllimport)
#endif

#define TTDCAPA_CALL __cdecl

/* Bumped when this header's layout or semantics change incompatibly. Compare it against
 * ttdcapa_abi_version() at load time if you resolve the DLL dynamically. */
#define TTDCAPA_ABI_VERSION 1u

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ttdcapa_status {
    TTDCAPA_OK = 0,
    TTDCAPA_E_INVALID_ARGUMENT = 1,  /* a required field was missing or nonsensical */
    TTDCAPA_E_ENGINE = 2,            /* the TTD replay engine could not open the trace */
    TTDCAPA_E_UNSUPPORTED_ARCH = 3,  /* the guest is neither x86 nor x64 */
    TTDCAPA_E_BAD_INPUT = 4,         /* an input file exists but could not be parsed */
    TTDCAPA_E_IO = 5,                /* an output file could not be written */
    TTDCAPA_E_CANCELLED = 6,         /* your cancel callback asked us to stop */
    TTDCAPA_E_INTERNAL = 7,          /* an unexpected failure inside a pass */
} ttdcapa_status;

typedef enum ttdcapa_log_level {
    TTDCAPA_LOG_INFO = 0,
    TTDCAPA_LOG_WARN = 1,
    TTDCAPA_LOG_ERROR = 2,
    /* The library's own narration: which stage started, how long a replay took, which export a
     * breakpoint landed on. Separated from INFO so a host can keep each pass's findings without
     * the running commentary around them -- one --scan-code run produces about five of the
     * former and twenty-five of the latter.
     *
     * Only produced when the pass's `verbose` option is set, so a host compiled before this
     * value existed can never be handed one. It is appended rather than inserted for the same
     * reason: INFO/WARN/ERROR keep the values hosts already compare against. Note that it sits
     * past ERROR while being the *least* severe level -- treat it as a category, not as a
     * threshold. */
    TTDCAPA_LOG_DEBUG = 3,
} ttdcapa_log_level;

/* A UTF-8 buffer owned by the library. `data` is NUL-terminated as a convenience, and
 * `length` excludes that terminator. Release with ttdcapa_string_free. */
typedef struct ttdcapa_string {
    const char* data;
    size_t length;
} ttdcapa_string;

/* Progress diagnostics, one complete line at a time, without a trailing newline. Called on
 * the thread that invoked the analysis. Pass NULL to let the library write to stderr, which
 * is what the command-line tool does. */
typedef void(TTDCAPA_CALL* ttdcapa_log_fn)(void* user, ttdcapa_log_level level, const char* message);

/* Polled periodically during long replays; return non-zero to stop early. A cancelled pass
 * returns TTDCAPA_E_CANCELLED and produces no output. */
typedef int(TTDCAPA_CALL* ttdcapa_cancel_fn)(void* user);

/* Fields shared by every pass. Embedded by value as the first member of each options struct
 * so the common plumbing is filled in the same way everywhere.
 *
 * Nothing may be appended to this struct. It is embedded *by value*, so growing it shifts every
 * field that follows it in each pass's options -- and `struct_size` cannot detect that, since it
 * only distinguishes a shorter tail, never a different interior. A new shared option goes at the
 * tail of each of the three pass structs instead, the way `rebuild_index` and `verbose` did. */
typedef struct ttdcapa_common_options {
    const wchar_t* trace_path;   /* required: the .run trace to analyse */
    ttdcapa_log_fn log;          /* optional: NULL means write diagnostics to stderr */
    void* log_user;
    ttdcapa_cancel_fn cancel;    /* optional: NULL means the pass runs to completion */
    void* cancel_user;
} ttdcapa_common_options;

/* --- 1. dynamic pass: the API-call report ------------------------------------------- */

typedef struct ttdcapa_extract_options {
    uint32_t struct_size;                /* = sizeof(ttdcapa_extract_options) */
    ttdcapa_common_options common;

    const wchar_t* sample_path;          /* optional on-disk sample, for accurate hashes */
    const wchar_t* win32_index_path;     /* optional; NULL searches next to the module */
    const wchar_t* report_path;          /* optional: also write the report JSON here */

    uint64_t max_calls;                  /* 0 = unlimited */
    uint32_t max_buffer;                 /* bytes kept from any one captured buffer; 0 = 256 */
    int no_metadata;                     /* non-zero disables metadata-driven arg decoding */
    int with_stack_args;                 /* non-zero: grab 4 stack slots for unknown APIs */

    /* Non-zero: delete an index file the engine cannot load and build a fresh one. The TTD SDK
     * refuses to replace a pre-existing .idx unless asked, so a trace carrying a stale one
     * otherwise replays unindexed on every run -- correct, but far slower, and out-params the
     * kernel wrote may not be recoverable. Same meaning as on the other two passes. */
    int rebuild_index;

    /* Non-zero: also emit TTDCAPA_LOG_DEBUG messages -- the pass's running commentary, which is
     * otherwise not produced at all. Leave at 0 (the default) and your log callback receives
     * only INFO/WARN/ERROR, which is what a host wanting a readable default log wants. Same
     * meaning as on the other two passes. */
    int verbose;

    /* Not an option -- an ABI shim, and it has to stay.
     *
     * This struct holds uint64_t members, so it is 8-aligned, and `verbose` used to end it at
     * offset 100 with four bytes of tail padding carrying it to 104. A new `int` appended
     * after `verbose` would land in exactly that padding: `sizeof` would not change, so a
     * host built against this header would send the same `struct_size` as one built before it
     * and the library could not tell them apart -- and worse, an older host's *indeterminate*
     * padding would be copied in and read as a set flag, silently turning an option on for a
     * caller that never asked. This filler occupies the padding so that everything after it
     * begins past the old struct's end, where `struct_size` can see it.
     *
     * Always zero. Do not read it, do not write it, and append new options after it, not here. */
    int reserved0;

    /* Non-zero: also run the seeking pass that re-reads the string arguments the sweep could
     * not see. Off by default, because it costs more than the rest of the pass put together.
     *
     * Arguments are decoded inside a call/return callback, whose memory view answers at
     * ThreadLocal fidelity -- what that thread touched near that position, and little else --
     * so a string the caller left in a heap buffer long before the call reads back as nothing
     * and the report keeps only the pointer. Most of those are settled for free at the call's
     * own return, where the callee has usually just read the string itself; that read happens
     * either way and this option does not affect it. What is left over can only be had by
     * seeking a cursor back to each call and asking at a stronger memory policy, one trace
     * seek apiece: on a 75 MB trace that is 2.2 s of extraction becoming 6.7 s, buying the
     * last 1% of string parameters (96.5% decoded, against 97.3%). Set this when that last
     * percent matters more than the time -- a rule that turns on one string can need it.
     *
     * Left at 0 you get the bare pointer where those strings would have been, which is also
     * what a host built against a header without this field gets. */
    int recover_strings;
} ttdcapa_extract_options;

/* Sweeps the trace and produces the TTD report JSON that capa-cpp matches rules against.
 * `out_json` is optional; pass NULL if `report_path` alone is enough. */
TTDCAPA_API ttdcapa_status TTDCAPA_CALL ttdcapa_extract_report(
    const ttdcapa_extract_options* options, ttdcapa_string* out_json);

/* --- 2. static pass: reconstructing runtime-created code ---------------------------- */

typedef struct ttdcapa_scan_code_options {
    uint32_t struct_size;                /* = sizeof(ttdcapa_scan_code_options) */
    ttdcapa_common_options common;

    /* Where the .bin snapshots go. The static matcher reads them as files, so this is
     * required even when you take the manifest in memory. NULL means the current directory. */
    const wchar_t* dump_dir;
    const wchar_t* manifest_path;        /* optional: also write the manifest JSON here */

    uint32_t max_scans_per_region;       /* cap on snapshots per region; 0 = unlimited */
    int include_data;                    /* non-zero: also reconstruct non-executable regions */
    int rebuild_index;                   /* non-zero: delete an unloadable .idx and rebuild */

    /* Host-memory budgets. Reconstruction holds a buffer the size of the region plus a log of
     * every write that landed in it, and a trace can always name a region bigger than the
     * machine analysing it; anything over budget is skipped with a diagnostic through the log
     * callback instead of exhausting the process. Both default when left at 0, and both can be
     * lifted with UINT64_MAX.
     *
     * max_region_bytes is per region. max_write_log_bytes covers every region's write log
     * *together*: all regions are recorded in one replay, so their logs are resident at once
     * and the sum is what has to be bounded. On reaching it the region holding the largest log
     * is dropped and the pass continues for the rest -- so a host that sizes this from a
     * per-region estimate will now under-budget it. */
    uint64_t max_region_bytes;           /* 0 = 256 MiB, per region */
    uint64_t max_write_log_bytes;        /* 0 = 1 GiB, across all regions */

    /* Non-zero: also emit TTDCAPA_LOG_DEBUG messages. See ttdcapa_extract_options.verbose. */
    int verbose;

    /* Not an option -- an ABI shim, and it has to stay.
     *
     * This struct holds uint64_t members, so it is 8-aligned, and `verbose` used to end it at
     * offset 100 with four bytes of tail padding carrying it to 104. A new `int` appended
     * after `verbose` would land in exactly that padding: `sizeof` would not change, so a
     * host built against this header would send the same `struct_size` as one built before it
     * and the library could not tell them apart -- and worse, an older host's *indeterminate*
     * padding would be copied in and read as a set flag, silently turning an option on for a
     * caller that never asked. This filler occupies the padding so that everything after it
     * begins past the old struct's end, where `struct_size` can see it.
     *
     * Always zero. Do not read it, do not write it, and append new options after it, not here. */
    int reserved0;

    /* Non-zero: leave the sample's own module images alone, watching only the regions the
     * discovery providers turn up (allocations, section views, protection changes).
     *
     * The default (0) also watches the main executable and every module loaded from outside
     * the Windows directories, because a packer that unpacks *in place* -- UPX and most of its
     * descendants -- never allocates, and so reconstructs to nothing at all without it. That
     * coverage is not free: an image the program writes across produces a snapshot per
     * generation, and a busy one can produce a great many. Set this when the trace is known
     * not to need it, or when the scan's cost matters more than catching an in-place packer.
     *
     * Sense is inverted deliberately, so a host built against a header without this field --
     * whose zeroed struct leaves it 0 -- keeps the module scanning it already had. */
    int no_scan_modules;
} ttdcapa_scan_code_options;

/* Reconstructs runtime-created regions into `dump_dir`. `out_manifest_json` is optional. */
TTDCAPA_API ttdcapa_status TTDCAPA_CALL ttdcapa_scan_code(
    const ttdcapa_scan_code_options* options, ttdcapa_string* out_manifest_json);

/* --- 3. static pass: when did the matched code actually run? ------------------------ */

typedef enum ttdcapa_hit_dedup {
    /* Split a capability's executions by gaps in its own execution: one row per invocation,
     * which is what reveals a routine's cadence (a beacon encrypting each check-in). */
    TTDCAPA_HIT_DEDUP_VISIT = 0,
    /* Split by gaps in the whole region's execution instead: coarser, answering "how many
     * separate bursts did this reconstructed region run". */
    TTDCAPA_HIT_DEDUP_REENTRY = 1,
} ttdcapa_hit_dedup;

typedef struct ttdcapa_code_hits_options {
    uint32_t struct_size;                /* = sizeof(ttdcapa_code_hits_options) */
    ttdcapa_common_options common;

    /* The matched addresses, as JSON: either a bare [va, ...] array or capa-cpp's static
     * `-o` records (objects carrying "vas" and "base"). Supply exactly one of these --
     * `records_json` for records you already hold, `records_path` to read them from disk. */
    const char* records_json;
    const wchar_t* records_path;

    const wchar_t* hits_path;            /* optional: also write the hit records here */

    uint64_t hit_gap;                    /* Sequence gap that splits visits; 0 = 256 */
    ttdcapa_hit_dedup dedup;
    int rebuild_index;                   /* non-zero: delete an unloadable .idx and rebuild */

    /* Non-zero: also emit TTDCAPA_LOG_DEBUG messages. See ttdcapa_extract_options.verbose. */
    int verbose;
} ttdcapa_code_hits_options;

/* Replays the trace with an execute watchpoint on each matched address. `out_hits_json` is
 * optional. An empty result is a success, not an error: it means nothing matched executed. */
TTDCAPA_API ttdcapa_status TTDCAPA_CALL ttdcapa_trace_code_hits(
    const ttdcapa_code_hits_options* options, ttdcapa_string* out_hits_json);

/* --- housekeeping -------------------------------------------------------------------- */

/* Releases a string produced by any of the calls above. Safe on a zeroed struct, and leaves
 * the struct zeroed so a double free is harmless. */
TTDCAPA_API void TTDCAPA_CALL ttdcapa_string_free(ttdcapa_string* string);

/* TTDCAPA_ABI_VERSION as compiled into the library. */
TTDCAPA_API uint32_t TTDCAPA_CALL ttdcapa_abi_version(void);

/* Human-readable library version, e.g. "ttd-capa 0.2.0". Static storage; do not free. */
TTDCAPA_API const char* TTDCAPA_CALL ttdcapa_version_string(void);

/* Human-readable form of a status. Static storage; do not free. */
TTDCAPA_API const char* TTDCAPA_CALL ttdcapa_status_message(ttdcapa_status status);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* TTDCAPA_H */
