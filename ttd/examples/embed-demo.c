/*
 * embed-demo -- the smallest useful consumer of ttdcapa.dll.
 *
 * Runs the dynamic pass over a trace, then the code-scan pass, printing what each produced
 * and routing the extractor's progress through this program's own logger. It is deliberately
 * plain C: if this compiles and runs against your build, the ABI is wired up correctly.
 *
 * Build (from ttd\, after building the solution):
 *
 *   cl /nologo /W4 /I include examples\embed-demo.c ^
 *      bin\x64\Release\ttdcapa.lib /Fe:bin\x64\Release\embed-demo.exe
 *
 * Run:
 *
 *   bin\x64\Release\embed-demo.exe <trace.run> [dump-dir]
 *
 * ttdcapa.dll, TTDReplay.dll and TTDReplayCPU.dll all have to sit next to the executable,
 * which is already the case for anything built into bin\x64\Release\.
 */
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "ttdcapa.h"

/* Note the default case. A library newer than the header you compiled against can only hand
 * you a level you know about -- TTDCAPA_LOG_DEBUG arrives only if you set `verbose`, which
 * this demo leaves at 0 -- but indexing a fixed table by a value from another binary is the
 * kind of thing worth not doing anyway. */
static void __cdecl on_log(void* user, ttdcapa_log_level level, const char* message) {
    const char* name;
    switch (level) {
        case TTDCAPA_LOG_WARN:  name = "warn";  break;
        case TTDCAPA_LOG_ERROR: name = "error"; break;
        case TTDCAPA_LOG_DEBUG: name = "debug"; break;
        case TTDCAPA_LOG_INFO:  name = "info";  break;
        default:                name = "?";     break;
    }
    fprintf(stderr, "[%s] %s: %s\n", (const char*)user, name, message);
}

/* Nothing here ever cancels; a real host would poll its own stop flag. */
static int __cdecl never_cancel(void* user) {
    (void)user;
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fwprintf(stderr, L"usage: embed-demo <trace.run> [dump-dir]\n");
        return 1;
    }
    const wchar_t* trace = argv[1];
    const wchar_t* dump_dir = (argc > 2) ? argv[2] : L"dumps";

    printf("%s (abi %u)\n", ttdcapa_version_string(), ttdcapa_abi_version());

    /* 1. The dynamic pass: every resolved API call, with decoded arguments and TTD
     *    positions. Hand the JSON to capa-cpp to turn it into capabilities. */
    ttdcapa_extract_options extract;
    memset(&extract, 0, sizeof(extract));
    extract.struct_size = sizeof(extract);
    extract.common.trace_path = trace;
    extract.common.log = on_log;
    extract.common.log_user = (void*)"extract";
    extract.common.cancel = never_cancel;

    ttdcapa_string report = { 0 };
    ttdcapa_status status = ttdcapa_extract_report(&extract, &report);
    if (status != TTDCAPA_OK) {
        fprintf(stderr, "extract failed: %s\n", ttdcapa_status_message(status));
        return 2;
    }
    printf("report JSON: %zu bytes\n", report.length);
    ttdcapa_string_free(&report);

    /* 2. The static pass: reconstruct whatever the program built at runtime. The snapshots
     *    are files because that is what the static matcher reads; the manifest that
     *    describes them comes back in memory. */
    ttdcapa_scan_code_options scan;
    memset(&scan, 0, sizeof(scan));
    scan.struct_size = sizeof(scan);
    scan.common.trace_path = trace;
    scan.common.log = on_log;
    scan.common.log_user = (void*)"scan-code";
    scan.dump_dir = dump_dir;
    scan.max_scans_per_region = 8;
    /* Left at 0, so the sample's own module images are watched too -- which is what catches a
     * packer that unpacks in place. Set it to skip them when that cost is not worth paying. */
    scan.no_scan_modules = 0;

    ttdcapa_string manifest = { 0 };
    status = ttdcapa_scan_code(&scan, &manifest);
    if (status != TTDCAPA_OK) {
        fprintf(stderr, "code scan failed: %s\n", ttdcapa_status_message(status));
        return 3;
    }
    printf("manifest JSON: %zu bytes (snapshots in %ls)\n", manifest.length, dump_dir);
    ttdcapa_string_free(&manifest);

    /* 3. would be ttdcapa_trace_code_hits(), once capa-cpp has matched the snapshots and
     *    told us which instruction addresses to watch. See docs/EMBEDDING.md. */
    return 0;
}
