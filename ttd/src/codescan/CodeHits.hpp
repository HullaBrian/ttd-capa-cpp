#ifndef CODESCAN_CODEHITS_HPP
#define CODESCAN_CODEHITS_HPP

#include "../status.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

// Execute-hit tracing: given the set of instruction VAs that capa-cpp's static scan
// matched capabilities at (the `vas` in its -o records), replay the trace once with an
// execute watchpoint on each and record, per VA, when it ran, in which thread, and how
// often. This is what lets a code-scan capability land in the timeline at the moment it
// actually ran, not just where the region was reconstructed.
//
// Dedup is "visit-coalescing": consecutive executions of a VA that are close together in
// the trace (a tight loop / one continuous run) collapse into a single visit, but a
// re-execution far later (a routine invoked again -- e.g. a beacon encrypting each C2
// check-in) starts a new visit. Two hits belong to the same visit while the gap between
// them, in TTD Sequence units, stays <= gapThreshold. Each emitted record is one visit:
// its first TTD position, thread, and hit count.
namespace codehits {
    struct Config {
        std::wstring trace;
        // The matched VAs, as JSON: a bare [va,...] array, or capa-cpp's -o records (objects
        // carrying "vas" and "base"). Read from `vasInput` when set; otherwise taken from
        // `vasJson`, so a host that already holds the records need not go through a file.
        std::filesystem::path vasInput;
        std::string vasJson;
        std::filesystem::path output;     // JSON hits output ([{va, position, tid, hits}, ...]); empty writes no file
        bool rebuildIndex = false;
        // Max gap (in TTD Sequence units) between consecutive hits of a VA for them to count
        // as the same visit. Larger -> more collapsing (toward one row per VA); smaller ->
        // splits finer. A tight loop's iterations are ~0-1 apart; distinct invocations are
        // typically hundreds+ apart, so the exact value is not sensitive.
        uint64_t gapThreshold = 256;
        // Safety cap on visits emitted per VA (pathological ping-ponging); extra hits fold
        // into the last visit's count.
        std::size_t maxVisitsPerVa = 256;
        // Dedup granularity. false (default, "visit"): split each VA's runs by gaps in *that
        // VA's own* execution. true ("reentry"): split by gaps in the whole *region's*
        // execution, so every capability in one invocation of the reconstructed region shares
        // the same invocation boundary. Region grouping comes from the records' "base".
        bool reentry = false;
        // Polled during the replay; returning true stops it early and yields Cancelled.
        std::function<bool()> cancelled;
    };

    // Replays the trace once with the watchpoints described above. `hitsJson`, when non-null,
    // also receives the records, so an embedding host can skip the round-trip through a file.
    ttdcapa::Status run(Config const& config, std::string* hitsJson = nullptr);
}

#endif
