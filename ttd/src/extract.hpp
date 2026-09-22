#ifndef TTDCAPA_EXTRACT_HPP
#define TTDCAPA_EXTRACT_HPP

#include "status.hpp"
#include "utils.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>

// The dynamic pass: sweep a TTD trace's call/return events and record every call that lands
// on a resolved module export, with its arguments decoded against the Win32 metadata index.
//
// This is the library form of what `ttdcapa-extract <trace.run>` does; the CLI in main.cpp
// and the C API in api/ttdcapa_api.cpp are both thin wrappers over it. Keeping the pipeline
// here (rather than in wmain, where it used to live) is what lets a host process embed the
// extractor instead of shelling out to the executable and parsing its output file.
namespace ttdcapa {
    struct ExtractConfig {
        std::filesystem::path trace;        // the .run trace to sweep
        std::filesystem::path sample;       // optional on-disk sample, for accurate hashes
        std::filesystem::path win32_index;  // empty searches the default locations
        uint64_t max_calls = 0;             // 0 means unlimited
        size_t max_buffer = 256;            // bytes kept from any one counted buffer
        bool no_metadata = false;           // force the pre-metadata heuristic capture
        // After the sweep, re-read whatever string arguments are still unread by seeking a
        // cursor back to each call and asking at a stronger memory policy. Most are already
        // settled for free at the call's return, which always happens and is unaffected by
        // this; the remainder cost one trace seek each and dominate the run, so they are
        // opt-in: on a 75 MB trace this takes extraction from 2.2 s to 6.7 s to decode a
        // further 1% of string parameters.
        bool recover_strings = false;
        // Only affects calls with no metadata: blindly grab four extra stack slots.
        bool with_stack_args = false;
        // Delete an index file the engine cannot load and build a fresh one. Without this a
        // trace whose .idx is stale replays unindexed -- correct, but far slower.
        bool rebuild_index = false;
        // Polled periodically during the sweep; returning true stops the replay early and
        // yields Cancelled. The report built so far is left in `out` either way.
        std::function<bool()> cancelled;
    };

    // Runs the whole dynamic pass into `out`. Loads the Win32 metadata index (unless
    // disabled) on the way in; that index is process-global and cached across calls.
    // On Cancelled, `out` still holds everything recorded before the caller stopped us.
    Status extractReport(ExtractConfig const& config, Report& out);
}

#endif
