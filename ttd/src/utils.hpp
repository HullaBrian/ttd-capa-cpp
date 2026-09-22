#ifndef UITLS_HPP
#define UITLS_HPP

#include "ttdutils.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <filesystem>

namespace ttdcapa {
    struct SampleHashes {
        std::string md5;
        std::string sha1;
        std::string sha256;
    };

    struct Report {
        std::string arch;
        std::string os_name;
        std::filesystem::path trace_path;
        ttdcapa::SampleHashes hashes;
        std::string sample_name;
        std::vector<ttdcapa::ImportRecord> imports;
        std::vector<ttdcapa::ExportRecord> exports;
        std::vector<ttdcapa::SectionRecord> sections;
        std::vector<std::string> strings;
        ttdcapa::ProcessRecord process;
    };

    // Process memory counters, for the --verbose progress lines.
    //
    // Peak rather than current: the largest things this tool holds are transient -- the
    // report DOM, the JSON text, a region's shadow buffer -- so a reading taken between
    // stages sees none of them. Zeroed if the query fails; this is diagnostic output and
    // never reports an error of its own.
    struct MemUsage {
        uint64_t working_set = 0;       // bytes, current
        uint64_t peak_working_set = 0;  // bytes, high-water
        uint64_t peak_commit = 0;       // bytes, high-water private commit
    };
    MemUsage processMemory();

    // "rss 123 MB  peak 456 MB  commit 789 MB", or empty if the query failed. Meant to be
    // appended to a progress line.
    std::string memoryLine();

    // Compute MD5/SHA1/SHA256 (lowercase hex) of a file's contents via Windows CNG. Returns empty strings on failure (e.g. file missing).
    SampleHashes hashFile(const std::filesystem::path& path);

    // Serializes a report to the capa-compatible TTD report JSON. Embedders hand this
    // straight to their matcher; the CLI writes it to a file with writeReport below.
    std::string renderReport(const Report& report);

    // Writes generated CAPA JSON report to specified location
    bool writeReport(const Report& report, std::filesystem::path outputFilePath);

    // Writes the same report without ever holding it whole: the document minus its calls
    // is serialized once, and the calls are streamed into the gap one at a time. This is
    // what writeReport uses; renderReport above stays for embedders that want the string.
    bool writeReportStream(const Report& report, std::filesystem::path outputFilePath);

    void initializeReport(Report& report, TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor, std::wstring samplePath);
};

#endif