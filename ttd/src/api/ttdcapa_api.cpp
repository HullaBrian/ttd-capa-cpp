// Implementation of the embedding API declared in include/ttdcapa.h.
//
// Everything here is glue: translate a C options struct into the internal config, install a
// diagnostics sink and cancellation predicate that call back into the host, run one of the
// three passes, and hand back the JSON. The analysis itself lives in extract.hpp and
// codescan/. No exception may cross this boundary, so every entry point ends in a catch-all.

#include "../../include/ttdcapa.h"

#include "../codescan/CodeHits.hpp"
#include "../codescan/CodeScan.hpp"
#include "../extract.hpp"
#include "../log.hpp"
#include "../status.hpp"
#include "../utils.hpp"

#include <cstddef>
#include <cstring>
#include <exception>
#include <filesystem>
#include <functional>
#include <new>
#include <string>

// Stamped by the build; the fallback keeps a direct compile of these sources working.
#ifndef TTDCAPA_VERSION
#define TTDCAPA_VERSION "0.2.0"
#endif

namespace {
    // The host's callbacks, reached from our own sink/predicate signatures.
    struct Callbacks {
        ttdcapa_log_fn log = nullptr;
        void* logUser = nullptr;
        ttdcapa_cancel_fn cancel = nullptr;
        void* cancelUser = nullptr;
    };

    void forwardLog(void* user, ttdcapa::log::Level level, char const* line) {
        auto const* callbacks = static_cast<Callbacks const*>(user);
        if (callbacks == nullptr || callbacks->log == nullptr) return;
        ttdcapa_log_level mapped = TTDCAPA_LOG_INFO;
        switch (level) {
            case ttdcapa::log::Level::Warn:  mapped = TTDCAPA_LOG_WARN;  break;
            case ttdcapa::log::Level::Error: mapped = TTDCAPA_LOG_ERROR; break;
            case ttdcapa::log::Level::Debug: mapped = TTDCAPA_LOG_DEBUG; break;
            case ttdcapa::log::Level::Info:  mapped = TTDCAPA_LOG_INFO;  break;
        }
        callbacks->log(callbacks->logUser, mapped, line);
    }

    std::function<bool()> cancelPredicate(Callbacks const& callbacks) {
        if (callbacks.cancel == nullptr) return {};
        ttdcapa_cancel_fn const fn = callbacks.cancel;
        void* const user = callbacks.cancelUser;
        return [fn, user] { return fn(user) != 0; };
    }

    ttdcapa_status toStatus(ttdcapa::Status status) {
        switch (status) {
            case ttdcapa::Status::Ok:              return TTDCAPA_OK;
            case ttdcapa::Status::InvalidArgument: return TTDCAPA_E_INVALID_ARGUMENT;
            case ttdcapa::Status::EngineFailed:    return TTDCAPA_E_ENGINE;
            case ttdcapa::Status::UnsupportedArch: return TTDCAPA_E_UNSUPPORTED_ARCH;
            case ttdcapa::Status::BadInput:        return TTDCAPA_E_BAD_INPUT;
            case ttdcapa::Status::IoFailed:        return TTDCAPA_E_IO;
            case ttdcapa::Status::Cancelled:       return TTDCAPA_E_CANCELLED;
            case ttdcapa::Status::Internal:        return TTDCAPA_E_INTERNAL;
        }
        return TTDCAPA_E_INTERNAL;
    }

    // A host compiled against an older header passes a smaller struct. Copying what it did
    // send into a zeroed struct of the current size means fields it never knew about read as
    // "not set", which is exactly what the defaults documented in the header mean.
    template <typename T>
    bool copyOptions(void const* raw, T& out) {
        if (raw == nullptr) return false;
        uint32_t declared = 0;
        std::memcpy(&declared, raw, sizeof(declared));  // struct_size is always the first member
        // Anything shorter than the common block is not a struct we can make sense of.
        if (declared < offsetof(T, common) + sizeof(ttdcapa_common_options)) return false;

        out = T{};
        std::memcpy(&out, raw, declared < sizeof(T) ? declared : sizeof(T));
        out.struct_size = sizeof(T);
        return true;
    }

    std::filesystem::path pathOf(wchar_t const* value) {
        return (value != nullptr && value[0] != L'\0') ? std::filesystem::path(value)
                                                       : std::filesystem::path();
    }

    // Hands a std::string over the ABI as a library-owned buffer. Returning false leaves the
    // caller's struct empty, which is what an allocation failure should look like to them.
    bool publish(std::string const& text, ttdcapa_string* out) {
        if (out == nullptr) return true;  // the caller only wanted the file
        out->data = nullptr;
        out->length = 0;

        char* buffer = new (std::nothrow) char[text.size() + 1];
        if (buffer == nullptr) return false;
        std::memcpy(buffer, text.data(), text.size());
        buffer[text.size()] = '\0';
        out->data = buffer;
        out->length = text.size();
        return true;
    }
}  // namespace

extern "C" {

ttdcapa_status TTDCAPA_CALL ttdcapa_extract_report(ttdcapa_extract_options const* options,
                                                  ttdcapa_string* out_json) {
    if (out_json != nullptr) *out_json = ttdcapa_string{};

    ttdcapa_extract_options opts;
    if (!copyOptions(options, opts)) return TTDCAPA_E_INVALID_ARGUMENT;
    if (opts.common.trace_path == nullptr) return TTDCAPA_E_INVALID_ARGUMENT;

    Callbacks callbacks{ opts.common.log, opts.common.log_user,
                         opts.common.cancel, opts.common.cancel_user };
    ttdcapa::log::ScopedSink sink(callbacks.log != nullptr ? &forwardLog : nullptr, &callbacks);
    // Off unless asked for, so a host built against a header without this field -- whose zeroed
    // struct leaves it 0 -- is never handed a TTDCAPA_LOG_DEBUG it cannot classify.
    ttdcapa::log::ScopedVerbosity verbosity(opts.verbose != 0);

    try {
        ttdcapa::ExtractConfig config;
        config.trace = opts.common.trace_path;
        config.sample = pathOf(opts.sample_path);
        config.win32_index = pathOf(opts.win32_index_path);
        config.max_calls = opts.max_calls;
        config.max_buffer = opts.max_buffer != 0 ? opts.max_buffer : 256;
        config.no_metadata = opts.no_metadata != 0;
        config.recover_strings = opts.recover_strings != 0;
        config.with_stack_args = opts.with_stack_args != 0;
        config.rebuild_index = opts.rebuild_index != 0;
        config.cancelled = cancelPredicate(callbacks);

        ttdcapa::Report report;
        ttdcapa::Status const status = ttdcapa::extractReport(config, report);
        if (status != ttdcapa::Status::Ok) return toStatus(status);

        std::filesystem::path const reportPath = pathOf(opts.report_path);
        if (!reportPath.empty() && !ttdcapa::writeReport(report, reportPath)) {
            return TTDCAPA_E_IO;
        }
        if (out_json != nullptr && !publish(ttdcapa::renderReport(report), out_json)) {
            return TTDCAPA_E_INTERNAL;
        }
        return TTDCAPA_OK;
    } catch (std::bad_alloc const&) {
        // "bad allocation" on its own leaves a host with nothing to act on.
        ttdcapa::log::err() << "[-] Out of memory analysing this trace\n";
        return TTDCAPA_E_INTERNAL;
    } catch (std::exception const& e) {
        ttdcapa::log::err() << "[-] " << e.what() << "\n";
        return TTDCAPA_E_INTERNAL;
    } catch (...) {
        return TTDCAPA_E_INTERNAL;
    }
}

ttdcapa_status TTDCAPA_CALL ttdcapa_scan_code(ttdcapa_scan_code_options const* options,
                                              ttdcapa_string* out_manifest_json) {
    if (out_manifest_json != nullptr) *out_manifest_json = ttdcapa_string{};

    ttdcapa_scan_code_options opts;
    if (!copyOptions(options, opts)) return TTDCAPA_E_INVALID_ARGUMENT;
    if (opts.common.trace_path == nullptr) return TTDCAPA_E_INVALID_ARGUMENT;

    Callbacks callbacks{ opts.common.log, opts.common.log_user,
                         opts.common.cancel, opts.common.cancel_user };
    ttdcapa::log::ScopedSink sink(callbacks.log != nullptr ? &forwardLog : nullptr, &callbacks);
    // Off unless asked for, so a host built against a header without this field -- whose zeroed
    // struct leaves it 0 -- is never handed a TTDCAPA_LOG_DEBUG it cannot classify.
    ttdcapa::log::ScopedVerbosity verbosity(opts.verbose != 0);

    try {
        codescan::Config config;
        config.trace = opts.common.trace_path;
        config.dumpDir = pathOf(opts.dump_dir);
        config.manifestPath = pathOf(opts.manifest_path);
        config.rebuildIndex = opts.rebuild_index != 0;
        config.maxScansPerRegion = opts.max_scans_per_region;
        config.includeData = opts.include_data != 0;
        // Inverted sense: a host that never set the field (or was built before it existed)
        // reads 0 here and keeps the module scanning that has always been the default.
        config.scanSampleModules = opts.no_scan_modules == 0;
        if (opts.max_region_bytes != 0) config.maxRegionBytes = opts.max_region_bytes;
        if (opts.max_write_log_bytes != 0) config.maxWriteLogBytes = opts.max_write_log_bytes;
        config.cancelled = cancelPredicate(callbacks);

        std::string manifest;
        ttdcapa::Status const status = codescan::run(config, &manifest);
        if (status != ttdcapa::Status::Ok) return toStatus(status);
        if (!publish(manifest, out_manifest_json)) return TTDCAPA_E_INTERNAL;
        return TTDCAPA_OK;
    } catch (std::bad_alloc const&) {
        // "bad allocation" on its own leaves a host with nothing to act on.
        ttdcapa::log::err() << "[-] Out of memory analysing this trace\n";
        return TTDCAPA_E_INTERNAL;
    } catch (std::exception const& e) {
        ttdcapa::log::err() << "[-] " << e.what() << "\n";
        return TTDCAPA_E_INTERNAL;
    } catch (...) {
        return TTDCAPA_E_INTERNAL;
    }
}

ttdcapa_status TTDCAPA_CALL ttdcapa_trace_code_hits(ttdcapa_code_hits_options const* options,
                                                    ttdcapa_string* out_hits_json) {
    if (out_hits_json != nullptr) *out_hits_json = ttdcapa_string{};

    ttdcapa_code_hits_options opts;
    if (!copyOptions(options, opts)) return TTDCAPA_E_INVALID_ARGUMENT;
    if (opts.common.trace_path == nullptr) return TTDCAPA_E_INVALID_ARGUMENT;
    // The matched addresses have to come from somewhere, and taking them from two places at
    // once would silently ignore one of them.
    bool const haveJson = opts.records_json != nullptr && opts.records_json[0] != '\0';
    bool const havePath = opts.records_path != nullptr && opts.records_path[0] != L'\0';
    if (haveJson == havePath) return TTDCAPA_E_INVALID_ARGUMENT;

    Callbacks callbacks{ opts.common.log, opts.common.log_user,
                         opts.common.cancel, opts.common.cancel_user };
    ttdcapa::log::ScopedSink sink(callbacks.log != nullptr ? &forwardLog : nullptr, &callbacks);
    // Off unless asked for, so a host built against a header without this field -- whose zeroed
    // struct leaves it 0 -- is never handed a TTDCAPA_LOG_DEBUG it cannot classify.
    ttdcapa::log::ScopedVerbosity verbosity(opts.verbose != 0);

    try {
        codehits::Config config;
        config.trace = opts.common.trace_path;
        if (havePath) {
            config.vasInput = opts.records_path;
        } else {
            config.vasJson = opts.records_json;
        }
        config.output = pathOf(opts.hits_path);
        config.rebuildIndex = opts.rebuild_index != 0;
        config.gapThreshold = opts.hit_gap != 0 ? opts.hit_gap : 256;
        config.reentry = (opts.dedup == TTDCAPA_HIT_DEDUP_REENTRY);
        config.cancelled = cancelPredicate(callbacks);

        std::string hits;
        ttdcapa::Status const status = codehits::run(config, &hits);
        if (status != ttdcapa::Status::Ok) return toStatus(status);
        if (!publish(hits, out_hits_json)) return TTDCAPA_E_INTERNAL;
        return TTDCAPA_OK;
    } catch (std::bad_alloc const&) {
        // "bad allocation" on its own leaves a host with nothing to act on.
        ttdcapa::log::err() << "[-] Out of memory analysing this trace\n";
        return TTDCAPA_E_INTERNAL;
    } catch (std::exception const& e) {
        ttdcapa::log::err() << "[-] " << e.what() << "\n";
        return TTDCAPA_E_INTERNAL;
    } catch (...) {
        return TTDCAPA_E_INTERNAL;
    }
}

void TTDCAPA_CALL ttdcapa_string_free(ttdcapa_string* string) {
    if (string == nullptr || string->data == nullptr) return;
    delete[] string->data;
    string->data = nullptr;
    string->length = 0;
}

uint32_t TTDCAPA_CALL ttdcapa_abi_version(void) {
    return TTDCAPA_ABI_VERSION;
}

char const* TTDCAPA_CALL ttdcapa_version_string(void) {
    return "ttd-capa " TTDCAPA_VERSION;
}

char const* TTDCAPA_CALL ttdcapa_status_message(ttdcapa_status status) {
    switch (status) {
        case TTDCAPA_OK:                 return "ok";
        case TTDCAPA_E_INVALID_ARGUMENT: return "invalid argument";
        case TTDCAPA_E_ENGINE:           return "the TTD replay engine could not open the trace";
        case TTDCAPA_E_UNSUPPORTED_ARCH: return "only x86 and x64 traces are supported in this version";
        case TTDCAPA_E_BAD_INPUT:        return "an input file could not be parsed";
        case TTDCAPA_E_IO:               return "an output file could not be written";
        case TTDCAPA_E_CANCELLED:        return "cancelled by the caller";
        case TTDCAPA_E_INTERNAL:         return "internal error";
    }
    return "unknown status";
}

}  // extern "C"
