#ifndef CODESCAN_CODESCAN_HPP
#define CODESCAN_CODESCAN_HPP

#include "../status.hpp"

#include <cstddef>
#include <filesystem>
#include <functional>
#include <string>

// Code-scan mode: reconstruct the contents of dynamically-created *executable* memory regions at
// the moments code actually executed in them, and dump each such snapshot to disk alongside a
// manifest JSON. capa-cpp's static analysis (`--scan-code-manifest`) then runs over the dumps,
// surfacing capabilities of unpacked / JIT'd / injected code that the call-based dynamic report
// cannot see.
//
// The manifest also carries a `modules` array: every module the trace loaded, with its base,
// size and named exports. A reconstructed region is not self-describing -- shellcode that
// resolved its imports with GetProcAddress holds a table of bare addresses, and every one of
// them points outside the region -- so this is what lets the static scan turn those addresses
// back into `api:` features. On a Cobalt Strike beacon it is the difference between 8 rules
// matching and 24.
//
// This is a self-contained pass: it opens its own TTD engine and does not touch the call-sweep
// path in extract.hpp.
namespace codescan {
    struct Config {
        std::wstring trace;                  // .run trace to analyze
        std::filesystem::path dumpDir;       // directory to write .bin snapshots into (created if absent)
        std::filesystem::path manifestPath;  // where to write the manifest JSON; empty writes no file
        bool rebuildIndex = false;           // delete an unloadable .idx and rebuild
        size_t maxScansPerRegion = 8;        // safety cap on snapshots emitted per region (0 = unlimited)
        bool includeData = false;            // also reconstruct/scan non-executable regions
        // Also watch the sample's own module images -- the main executable and anything
        // loaded from outside the Windows directories.
        //
        // A packer that unpacks *in place* never allocates: UPX and most of its
        // descendants decompress over their own image and jump into it. The providers
        // above watch allocations and section views, and NtMapViewOfSection's explicitly
        // rejects anything overlapping a loaded module, so that whole family of samples
        // reconstructs to nothing at all. Watching the sample's image closes it: the
        // writes are the unpacking, and the first execution after them is the unpacked
        // entry point.
        //
        // System modules stay out. Their writes are the loader's -- relocations, IAT
        // fixups, .data -- and reconstructing forty snapshots of ntdll to learn that is
        // not a trade worth making.
        bool scanSampleModules = true;
        // Host-memory budgets, both disableable with 0. Reconstruction holds a buffer of the
        // region's size plus a log of every write that landed in it, and a trace can always name a
        // region bigger than the machine analysing it -- these decide whether such a region is
        // skipped with a diagnostic or taken as far as the allocator allows.
        //
        // maxRegionBytes is per region. maxWriteLogBytes is a ceiling on every region's write log
        // *together*: all regions are recorded in a single replay, so their logs are resident at
        // once and the sum is what has to be bounded. On reaching it the region holding the
        // largest log is dropped and the pass continues for the rest.
        uint64_t maxRegionBytes = 256ull * 1024 * 1024;
        uint64_t maxWriteLogBytes = 1024ull * 1024 * 1024;
        // Polled between regions and during each region's replay; returning true stops the
        // scan early and yields Cancelled.
        std::function<bool()> cancelled;
    };

    // Runs the whole code-scan pipeline. The snapshots themselves always go to `dumpDir`,
    // since the static matcher reads them as files; `manifestJson`, when non-null, also
    // receives the manifest so an embedding host need not read it back off disk.
    ttdcapa::Status run(Config const& config, std::string* manifestJson = nullptr);
}

#endif
