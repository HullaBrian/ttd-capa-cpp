// ttdcapa-extract: command-line front end for the TTD capability extractor.
//
//   ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]
//                   [--max-calls N] [--with-stack-args] [--win32-index <path>]
//                   [--no-metadata] [--max-buffer N] [--recover-strings] [--rebuild-index]
//   ttdcapa-extract <trace.run> --scan-code [--dump-dir <dir>] [--code-manifest <path>]
//                   [--max-code-scans N] [--scan-data] [--no-scan-modules] [--rebuild-index]
//                   [--max-region-bytes N] [--max-write-log-bytes N]
//   ttdcapa-extract <trace.run> --trace-code-hits <records.json> [--hits-output <path>]
//                   [--hit-gap N] [--hit-dedup visit|reentry]
//   ttdcapa-extract --dump-sig <ApiName>
//
// The analysis itself lives in extract.hpp (the call sweep), codescan/CodeScan.hpp (region
// reconstruction) and codescan/CodeHits.hpp (execute-hit tracing); this file only parses
// arguments and picks one of them. The same three passes are reachable in-process through
// the C API in include/ttdcapa.h, so a host program can embed the extractor rather than
// shell out to this executable.
//
// x64 and x86 traces are both supported, including WoW64. Bitness is decided per call from
// the module owning the target rather than once for the trace: SystemInfo reports the
// *recording machine's* architecture, which says nothing about the guest, and a WoW64
// process runs both widths at once.

#include <cassert>
#define DBG_ASSERT(cond) assert(cond)

#include "abi.hpp"
#include "codescan/CodeHits.hpp"
#include "codescan/CodeScan.hpp"
#include "extract.hpp"
#include "log.hpp"
#include "status.hpp"
#include "ttdutils.hpp"
#include "utils.hpp"
#include "win32meta.hpp"

#include <cerrno>
#include <cstdint>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <iostream>
#include <new>
#include <string>

using namespace ttdcapa;

namespace {
    struct Options {
        std::filesystem::path trace;
        std::filesystem::path sample;       // optional on-disk sample for hashing
        std::filesystem::path output;       // where the report JSON goes
        std::filesystem::path win32_index;  // empty means search the default locations
        std::string dump_sig;               // print one signature and exit; no trace needed
        uint64_t max_calls = 0;             // 0 means unlimited
        size_t max_buffer = 256;            // bytes kept from any one counted buffer
        bool no_metadata = false;           // force the pre-metadata heuristic capture
        bool recover_strings = false;       // opt-in seeking pass for strings still unread after the sweep
        // Only affects calls with no metadata: blindly grab four extra stack slots.
        // Functions we have a signature for always capture their true arity.
        bool with_stack_args = false;

        // Code-scan mode: reconstruct dynamically-created executable regions and dump the
        // snapshots capa-cpp's static analysis should scan, instead of the call sweep.
        bool scan_code = false;
        std::filesystem::path dump_dir;        // directory for .bin snapshots (default: cwd)
        std::filesystem::path code_manifest;   // manifest JSON path (default: ttd-code-manifest.json)
        bool rebuild_index = false;            // delete an unloadable .idx and rebuild it
        size_t max_code_scans = 8;             // cap snapshots emitted per region (0 = unlimited)
        bool include_data = false;             // also reconstruct/scan non-executable regions
        bool no_scan_modules = false;          // --no-scan-modules: leave the sample's own images alone
        // Per-region host-memory budgets; 0 disables either. Defaults live in codescan::Config.
        uint64_t max_region_bytes = 0;         // --max-region-bytes: skip regions larger than this
        uint64_t max_write_log_bytes = 0;      // --max-write-log-bytes: ceiling on all write logs together
        bool max_region_bytes_set = false;
        bool max_write_log_bytes_set = false;

        // Execute-hit tracing mode: replay with execute watchpoints on the instruction VAs
        // a static scan matched, recording when each ran. Active when code_hits_input is set.
        std::filesystem::path code_hits_input;   // --trace-code-hits <vas-or-records.json>
        std::filesystem::path code_hits_output;  // --hits-output <path> (default: ttd-code-hits.json)
        uint64_t code_hits_gap = 256;            // --hit-gap: Sequence gap that splits a VA's visits
        bool code_hits_reentry = false;          // --hit-dedup reentry: split by region execution, not per-VA
    };

    // Parses a byte count for the memory budgets: decimal, or hex with an explicit 0x prefix
    // because every size this tool prints is hex. Anything it cannot consume in full is
    // rejected rather than partially read -- "512MB" would otherwise become 512 and skip every
    // region, and a typo would become 0, which means *no limit* and quietly removes the guard
    // the caller was reaching for. A bare leading zero stays decimal; nobody means octal here.
    bool parse_byte_count(wchar_t const* text, uint64_t& out) {
        if (text == nullptr || text[0] == L'\0') return false;

        int const base = (text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) ? 16 : 10;
        wchar_t* end = nullptr;
        errno = 0;
        unsigned long long const value = std::wcstoull(text, &end, base);
        if (end == text || *end != L'\0' || errno == ERANGE) {
            return false;
        }

        out = static_cast<uint64_t>(value);
        return true;
    }

    bool parse_args(int argc, wchar_t** argv, Options& opt) {
        for (int i = 1; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--sample" && i + 1 < argc) {
                opt.sample = argv[++i];
            }
            else if ((a == L"-o" || a == L"--output") && i + 1 < argc) {
                opt.output = argv[++i];
            }
            else if (a == L"--max-calls" && i + 1 < argc) {
                opt.max_calls = std::wcstoull(argv[++i], nullptr, 10);
            }
            else if (a == L"--with-stack-args") {
                opt.with_stack_args = true;
            }
            else if (a == L"--win32-index" && i + 1 < argc) {
                opt.win32_index = argv[++i];
            }
            else if (a == L"--no-metadata") {
                opt.no_metadata = true;
            }
            else if (a == L"--recover-strings") {
                opt.recover_strings = true;
            }
            else if (a == L"--max-buffer" && i + 1 < argc) {
                opt.max_buffer = static_cast<size_t>(std::wcstoull(argv[++i], nullptr, 10));
            }
            else if (a == L"--dump-sig" && i + 1 < argc) {
                opt.dump_sig = convertWstringToString(argv[++i]);
            }
            else if (a == L"--scan-code") {
                opt.scan_code = true;
            }
            else if (a == L"--dump-dir" && i + 1 < argc) {
                opt.dump_dir = argv[++i];
            }
            else if (a == L"--code-manifest" && i + 1 < argc) {
                opt.code_manifest = argv[++i];
            }
            else if (a == L"--rebuild-index") {
                opt.rebuild_index = true;
            }
            else if (a == L"--max-code-scans" && i + 1 < argc) {
                opt.max_code_scans = static_cast<size_t>(std::wcstoull(argv[++i], nullptr, 10));
            }
            else if (a == L"--scan-data") {
                opt.include_data = true;
            }
            else if (a == L"--no-scan-modules") {
                opt.no_scan_modules = true;
            }
            else if (a == L"--max-region-bytes" && i + 1 < argc) {
                if (!parse_byte_count(argv[++i], opt.max_region_bytes)) {
                    log::err() << "--max-region-bytes takes a byte count (decimal, or hex as 0x...); "
                                  "0 removes the limit\n";
                    return false;
                }
                opt.max_region_bytes_set = true;
            }
            else if (a == L"--max-write-log-bytes" && i + 1 < argc) {
                if (!parse_byte_count(argv[++i], opt.max_write_log_bytes)) {
                    log::err() << "--max-write-log-bytes takes a byte count (decimal, or hex as 0x...); "
                                  "0 removes the limit\n";
                    return false;
                }
                opt.max_write_log_bytes_set = true;
            }
            else if (a == L"--trace-code-hits" && i + 1 < argc) {
                opt.code_hits_input = argv[++i];
            }
            else if (a == L"--hits-output" && i + 1 < argc) {
                opt.code_hits_output = argv[++i];
            }
            else if (a == L"--hit-gap" && i + 1 < argc) {
                opt.code_hits_gap = std::wcstoull(argv[++i], nullptr, 10);
            }
            else if (a == L"--hit-dedup" && i + 1 < argc) {
                opt.code_hits_reentry = (std::wstring(argv[++i]) == L"reentry");
            }
            else if (!a.empty() && a[0] == L'-') {
                log::err() << "unknown option\n";
                return false;
            }
            else if (opt.trace.empty()) {
                opt.trace = a;
            }
            else {
                log::err() << "unexpected positional argument\n";
                return false;
            }
        }
        // --dump-sig is a metadata-only debug mode, so it doesn't need a trace.
        return !opt.trace.empty() || !opt.dump_sig.empty();
    }

    // Print one function's decoded signature and exit. Lets the metadata index and the
    // ABI classification be checked without waiting on a trace replay.
    int dumpSignature(const std::string& api) {
        const win32meta::FuncSig* sig = win32meta::index().lookup(api);
        if (sig == nullptr) {
            log::err() << "[-] '" << api << "' is not in the metadata index\n";
            return 3;
        }
        // A signature with no x86 layout is one the 32-bit decoder declines, so calls to it
        // in a 32-bit trace fall back to the heuristic capture. Saying so here is what makes
        // that visible without replaying a trace to find out.
        std::vector<uint16_t> x86Offsets;
        bool const x86Ok = x86StackLayout(*sig, x86Offsets);

        std::cout << sig->name << "  dll=" << sig->dll
                  << "  params=" << static_cast<int>(sig->paramCount)
                  << (sig->hiddenRetPtr() ? "  [hidden-return-pointer]" : "")
                  << (sig->unsupported() ? "  [unsupported]" : "")
                  << (x86Ok ? "" : "  [no x86 layout]") << "\n";
        for (uint8_t i = 0; i < sig->paramCount; ++i) {
            const win32meta::ParamSig& p = sig->params[i];
            std::cout << "  slot " << static_cast<int>(p.slot) << "  " << p.name
                      << " : " << p.type << "  (" << win32meta::kindName(p.kind) << ")";
            if (x86Ok) std::cout << "  x86@esp+" << (4 + x86Offsets[i]);
            if (p.isIn()) std::cout << " in";
            if (p.isOut()) std::cout << " out";
            if (p.attrs & win32meta::AttrOptional) std::cout << " optional";
            if (p.auxKind == win32meta::AuxKind::BytesFromParam) std::cout << "  bytes=param[" << p.auxValue << "]";
            if (p.auxKind == win32meta::AuxKind::CountFromParam) std::cout << "  count=param[" << p.auxValue << "]";
            if (p.auxKind == win32meta::AuxKind::CountConst) std::cout << "  count=" << p.auxValue;
            if (p.hasEnum()) std::cout << "  enum=" << win32meta::index().enumName(p.enumIndex);
            std::cout << "\n";
        }
        return 0;
    }

    void usage() {
        log::err() << "Usage: ttdcapa-extract <trace.run> [--sample <sample.exe>] [-o <out.json>]\n"
                      "                       [--max-calls N] [--with-stack-args]\n"
                      "                       [--win32-index <path>] [--no-metadata] [--max-buffer N]\n"
                      "                       [--recover-strings] [--rebuild-index]\n"
                      "       ttdcapa-extract <trace.run> --scan-code [--dump-dir <dir>]\n"
                      "                       [--code-manifest <path>] [--max-code-scans N]\n"
                      "                       [--scan-data] [--no-scan-modules] [--rebuild-index]\n"
                      "                       [--max-region-bytes N] [--max-write-log-bytes N]\n"
                      "       ttdcapa-extract <trace.run> --trace-code-hits <records.json>\n"
                      "                       [--hits-output <path>] [--hit-gap N]\n"
                      "                       [--hit-dedup visit|reentry]\n"
                      "       ttdcapa-extract --dump-sig <ApiName>\n";
    }
int runTool(int argc, wchar_t** argv) {
    // The narration is the point of a command-line run -- a long replay with nothing on stderr
    // reads as a hang. The library defaults the other way, so an embedding host gets each pass's
    // findings without its commentary unless it asks (ttdcapa.h's `verbose`).
    log::setVerbose(true);

    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage();
        return 1;
    }

    // Code-scan mode: reconstruct executable regions and dump the snapshots capa-cpp's
    // static analysis scans. Self-contained -- no Win32 metadata, no call sweep.
    if (opt.scan_code) {
        codescan::Config cfg;
        cfg.trace = opt.trace.wstring();
        cfg.dumpDir = opt.dump_dir;
        cfg.manifestPath = opt.code_manifest.empty()
            ? std::filesystem::path(L"ttd-code-manifest.json")
            : opt.code_manifest;
        cfg.rebuildIndex = opt.rebuild_index;
        cfg.maxScansPerRegion = opt.max_code_scans;
        cfg.includeData = opt.include_data;
        cfg.scanSampleModules = !opt.no_scan_modules;
        if (opt.max_region_bytes_set) cfg.maxRegionBytes = opt.max_region_bytes;
        if (opt.max_write_log_bytes_set) cfg.maxWriteLogBytes = opt.max_write_log_bytes;
        Status status = codescan::run(cfg);
        // Every region is recorded in one replay, so this is the peak of all their write
        // logs and instruction sets together -- the number the two budgets are trying to
        // bound, and the one to compare them against when a scan dies.
        log::dbg() << "[+] After code scan: " << memoryLine() << "\n";
        if (status != Status::Ok) log::err() << "[-] " << statusMessage(status) << "\n";
        return exitCode(status);
    }

    // Execute-hit tracing: replay once with execute watchpoints on the instruction VAs a
    // static scan matched, so code capabilities land at real execution positions.
    if (!opt.code_hits_input.empty()) {
        codehits::Config cfg;
        cfg.trace = opt.trace.wstring();
        cfg.vasInput = opt.code_hits_input;
        cfg.output = opt.code_hits_output.empty()
            ? std::filesystem::path(L"ttd-code-hits.json")
            : opt.code_hits_output;
        cfg.rebuildIndex = opt.rebuild_index;
        cfg.gapThreshold = opt.code_hits_gap;
        cfg.reentry = opt.code_hits_reentry;
        Status status = codehits::run(cfg);
        if (status != Status::Ok) log::err() << "[-] " << statusMessage(status) << "\n";
        return exitCode(status);
    }

    if (!opt.dump_sig.empty()) {
        std::string err;
        if (!opt.no_metadata && !win32meta::loadIndex(opt.win32_index, err)) {
            log::err() << "[-] " << err << "\n";
            return 3;
        }
        return dumpSignature(opt.dump_sig);
    }

    ExtractConfig cfg;
    cfg.trace = opt.trace;
    cfg.sample = opt.sample;
    cfg.win32_index = opt.win32_index;
    cfg.max_calls = opt.max_calls;
    cfg.max_buffer = opt.max_buffer;
    cfg.no_metadata = opt.no_metadata;
    cfg.recover_strings = opt.recover_strings;
    cfg.with_stack_args = opt.with_stack_args;
    cfg.rebuild_index = opt.rebuild_index;

    Report report;
    Status status = extractReport(cfg, report);
    if (status != Status::Ok) {
        log::err() << "[-] " << statusMessage(status) << "\n";
        return exitCode(status);
    }

    // The sweep and the report write are the two stages that decide whether this tool
    // survives a large trace, and they fail differently -- the sweep by how many calls
    // it accumulated, the write by how large the JSON of them is. Reporting the peak
    // after each says which one to reach for a budget over.
    log::dbg() << "[+] After extraction: " << memoryLine() << "\n";

    if (!writeReport(report, opt.output)) {
        return exitCode(Status::IoFailed);
    }
    log::dbg() << "[+] After report write: " << memoryLine() << "\n";

    log::err() << "[!] Exiting...\n";
    return 0;
}
}  // namespace

int wmain(int argc, wchar_t** argv) {
    // A pass that runs out of memory on a big trace should say so and exit, not abort through
    // std::terminate with a Windows error box and no explanation of which trace did it.
    try {
        return runTool(argc, argv);
    } catch (std::bad_alloc const&) {
        log::err() << "[-] Out of memory. Try --max-calls, a lower --max-code-scans, or tighter\n"
                      "    --max-region-bytes / --max-write-log-bytes budgets.\n";
        return exitCode(Status::Internal);
    } catch (std::exception const& e) {
        log::err() << "[-] " << e.what() << "\n";
        return exitCode(Status::Internal);
    }
}
