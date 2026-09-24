#include "utils.hpp"
#include "abi.hpp"
#include "ttd_pe_utils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
// PSAPI_VERSION 2 is what makes psapi.h declare the K32-prefixed entry points,
// which live in kernel32 -- so this costs no extra import library.
#define PSAPI_VERSION 2
#include <psapi.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <bcrypt.h>

#include <nlohmann/json.hpp>

#pragma comment(lib, "bcrypt.lib")

namespace ttdcapa {
    MemUsage processMemory() {
        PROCESS_MEMORY_COUNTERS counters{};
        counters.cb = sizeof(counters);
        if (!K32GetProcessMemoryInfo(GetCurrentProcess(), &counters, sizeof(counters))) {
            return {};
        }

        MemUsage usage;
        usage.working_set = static_cast<uint64_t>(counters.WorkingSetSize);
        usage.peak_working_set = static_cast<uint64_t>(counters.PeakWorkingSetSize);
        // Commit, not working set, is what decides whether the next allocation throws: a
        // process can be trimmed out of its working set and still be at the commit limit.
        usage.peak_commit = static_cast<uint64_t>(counters.PeakPagefileUsage);
        return usage;
    }

    std::string memoryLine() {
        MemUsage const usage = processMemory();
        if (usage.peak_working_set == 0) return {};

        char buffer[96];
        std::snprintf(buffer, sizeof(buffer), "rss %.0f MB  peak %.0f MB  commit %.0f MB",
                      usage.working_set / 1048576.0, usage.peak_working_set / 1048576.0,
                      usage.peak_commit / 1048576.0);
        return buffer;
    }

    namespace {
        std::string to_hex(const std::vector<uint8_t>& bytes) {
            static const char* digits = "0123456789abcdef";
            std::string out;
            out.reserve(bytes.size() * 2);

            for (uint8_t b : bytes) {
                out.push_back(digits[b >> 4]);
                out.push_back(digits[b & 0x0f]);
            }

            return out;
        }

        // Hash an in-memory buffer with a single CNG algorithm.
        std::string hashBuffer(LPCWSTR alg, const std::vector<uint8_t>& data) {
            BCRYPT_ALG_HANDLE hAlg = nullptr;
            if (!BCRYPT_SUCCESS(::BCryptOpenAlgorithmProvider(&hAlg, alg, nullptr, 0))) {
                return {};
            }

            DWORD hash_len = 0, cb = 0;
            ::BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hash_len), sizeof(hash_len), &cb, 0);

            BCRYPT_HASH_HANDLE hHash = nullptr;
            std::string result;
            if (BCRYPT_SUCCESS(::BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0))) {
                if (BCRYPT_SUCCESS(::BCryptHashData(
                    hHash, const_cast<PUCHAR>(data.data()), static_cast<ULONG>(data.size()), 0))) {
                    std::vector<uint8_t> digest(hash_len);
                    if (BCRYPT_SUCCESS(::BCryptFinishHash(hHash, digest.data(), hash_len, 0))) {
                        result = to_hex(digest);
                    }
                }
                ::BCryptDestroyHash(hHash);
            }
            ::BCryptCloseAlgorithmProvider(hAlg, 0);
            return result;
        }

    }  // namespace

    SampleHashes hashFile(const std::filesystem::path& path) {
        SampleHashes out;

        std::ifstream f(path, std::ios::binary);
        if (!f) {
            return out;
        }
        std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

        out.md5 = hashBuffer(BCRYPT_MD5_ALGORITHM, data);
        out.sha1 = hashBuffer(BCRYPT_SHA1_ALGORITHM, data);
        out.sha256 = hashBuffer(BCRYPT_SHA256_ALGORITHM, data);
        return out;
    }

    void initializeReport(Report& report, TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor, std::wstring samplePath) {
        report.arch = "x64";
        report.os_name = "windows";
        report.process.ppid = 0;  // not exposed by TTD :(
        
        size_t mod_count = engine->GetModuleCount();
        TTD::Replay::Module const* mods = engine->GetModuleList();

        // exact function-entry VA -> (module, api)
        std::unordered_map<uint64_t, std::pair<std::string, std::string>> api_by_va;

        // Identify the main module (first image whose name ends in ".exe").
        int mainIndex = -1;
        for (size_t i = 0; i < mod_count; ++i) {
            std::wstring name = mods[i].pName ? mods[i].pName : L"";
            if (name.size() >= 4) {
                std::wstring ext = name.substr(name.size() - 4);
                for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));  // Lowercase name
                if (ext == L".exe") {
                    mainIndex = static_cast<int>(i);
                    break;
                }
            }
        }

        if (mainIndex == -1) {
            ttdcapa::log::werr() << L"[-] Unable to resolve main module!\n";
            return;
        }

        TTD::GuestAddress mbase = mods[mainIndex].Address;
        std::wstring full = mods[mainIndex].pName ? mods[mainIndex].pName : L"";
        size_t slash = full.find_last_of(L"\\/");
        report.sample_name = convertWstringToString( slash == std::wstring::npos ? full : full.substr(slash + 1));

        auto try_parse = [&](TTD::Replay::Position p) -> bool {
            cursor->SetPosition(p);

            report.imports.clear();
            report.sections.clear();

            std::vector<std::pair<uint64_t, std::string>> exps;
            bool ok = getModuleImports(&cursor, mbase, report.imports);
            ok = ttdcapa::getModuleSections(&cursor, mbase, report.sections) && ok;

            // The main image's PE format is what the report calls the trace's
            // architecture. A WoW64 trace also holds 64-bit system modules, but the
            // process it recorded is the 32-bit one.
            ModuleFormat format;
            if (getModuleFormat(&cursor, mbase, format)) {
                report.arch = archName(format);
            }

            if (getModuleExports(&cursor, mbase, exps)) {
                for (auto& e : exps) {
                    ExportRecord exportRecord;
                    exportRecord.name = e.second;
                    exportRecord.va = (TTD::GuestAddress) e.first;
                    report.exports.push_back(exportRecord);
                }
            }

            return ok && !report.sections.empty();
        };

        if (!try_parse(engine->GetLastPosition())) {
            try_parse(TTD::Replay::Position::Min);
        }

        cursor->SetPosition(engine->GetLastPosition());
        getModuleStrings(&cursor, mbase, report.strings);

        if (!samplePath.empty()) {
            report.hashes = hashFile(samplePath);
            if (report.sample_name.empty()) {
                report.process.name = report.sample_name;
            }
        }

        size_t thread_count = engine->GetThreadCount();
        TTD::Replay::ThreadInfo const* thread_list = engine->GetThreadList();
        for (size_t i = 0; i < thread_count; ++i) {
            report.process.threads.push_back(static_cast<uint64_t>(thread_list[i].UniqueId));
        }
    }

    namespace {
        // One call object, exactly as the report has always carried it.
        //
        // Extracted so the streaming writer and the in-memory renderer cannot drift apart:
        // they emit the same bytes because they call the same function, not because two
        // implementations happen to agree.
        nlohmann::json renderCall(const CallRecord& callRecord) {
            using json = nlohmann::json;
            json call;

            call["tid"] = callRecord.tid;
            call["seq"] = callRecord.seq;
            call["position"] = callRecord.position;
            // Absent, never "0:0", when the call did not return: an unreturned call is
            // a real state, and a zero position would read as an instant return.
            if (!callRecord.return_position.empty()) {
                call["returnPosition"] = callRecord.return_position;
            }
            // Only when the call went through a thunk, so a report without any is unchanged.
            if (callRecord.via != 0) {
                call["via"] = callRecord.via;
            }
            if (callRecord.ambiguous) {
                call["ambiguous"] = true;
            }

            // Proper UTF-8, not a wchar_t-per-byte truncation: module names are ASCII in
            // practice, but a non-ASCII one would otherwise be mangled rather than encoded.
            call["module"] = convertWstringToString(callRecord.module);

            call["api"] = callRecord.api;
            // No signature: the values below came from a fixed grab of argument
            // registers, not from a prototype, so some of them are whatever the
            // previous call left behind. Say so rather than leaving every consumer
            // to infer it from the absence of "params" -- a reader who sees four
            // unnamed values has no way to know the function takes none.
            if (!callRecord.metadata) {
                call["signature"] = false;
            }
            // Always an array, even when empty -- a zero-parameter function is a
            // real result, not a missing field.
            call["args"] = json::array();
            for (const ArgValue& argValue : callRecord.args) {
                if (std::holds_alternative<int64_t>(argValue)) {
                    call["args"].push_back(std::get<int64_t>(argValue));
                } else {
                    call["args"].push_back(std::get<std::string>(argValue));
                }
            }

            // The rich, metadata-derived view. capa matches on "args"; this is for
            // ttd-timeline and human triage, so it can afford to be verbose. Absent
            // entirely when we had no signature, so consumers can tell "no
            // parameters" apart from "we didn't know".
            if (callRecord.metadata) {
                call["params"] = json::array();
            }
            for (const DecodedArg& decoded : callRecord.params) {
                json param;
                param["name"] = decoded.name ? decoded.name : "";
                param["type"] = decoded.type ? decoded.type : "";
                param["kind"] = win32meta::kindName(decoded.kind);
                param["value"] = decoded.raw;
                if (decoded.has_str) {
                    param["str"] = decoded.str;
                    // The string stopped before its terminator, because the trace
                    // recorded no further bytes or because the cap was reached. A
                    // reader must never be shown a partial name that looks whole:
                    // 'WakeAllC' is otherwise indistinguishable from 'ReadFile'.
                    if (decoded.str_truncated) {
                        param["str_truncated"] = true;
                    }
                }
                if (decoded.has_deref) {
                    param["deref"] = decoded.deref;
                }
                if (decoded.has_fval) {
                    param["float"] = decoded.fval;
                }
                if (decoded.enum_index != 0xFFFFFFFFu) {
                    // The index records the enum a parameter's type *ultimately*
                    // refers to, following pointers to get there. For a scalar that
                    // enum describes the argument itself; for a pointer-to-enum it
                    // describes the pointee, which only exists once the callee has
                    // filled it in. Decoding the raw value in that second case
                    // decomposes an address into flag names -- which is how every
                    // VirtualProtect call came to report its lpflOldProtect stack
                    // pointer as thirteen page-protection bits.
                    if (decoded.kind == win32meta::ArgKind::Enum) {
                        std::vector<std::string> names =
                            win32meta::index().decodeEnum(decoded.enum_index, decoded.raw);
                        if (!names.empty()) {
                            param["flags"] = names;
                        }
                    } else if (isPointerKind(decoded.kind) && decoded.has_deref) {
                        // A separate key, so no existing consumer changes meaning:
                        // "flags" has always meant "the argument decodes to these".
                        std::vector<std::string> names =
                            win32meta::index().decodeEnum(decoded.enum_index, decoded.deref);
                        if (!names.empty()) {
                            param["derefFlags"] = names;
                        }
                    }
                }
                if (!decoded.bytes.empty()) {
                    param["bytes"] = to_hex(decoded.bytes);
                }
                if (decoded.is_out) {
                    param["out"] = true;
                }
                if (decoded.from_return) {
                    param["at_return"] = true;
                }
                call["params"].push_back(std::move(param));
            }

            call["ret"] = callRecord.has_ret ? callRecord.ret : 0;
            return call;
        }

        // The whole document with `calls` set to whatever is handed in -- the real array for
        // renderReport, a sentinel string for the streaming writer. Everything except the
        // calls is built once, here, so nlohmann decides key order and escaping for both
        // paths and neither has to know what that order is.
        nlohmann::json renderSkeleton(const Report& report, nlohmann::json calls) {
            using json = nlohmann::json;
            json doc;

            doc["version"] = 1;

            doc["trace"]["path"] = report.trace_path;
            doc["trace"]["arch"] = report.arch;
            doc["trace"]["os"] = report.os_name;

            doc["sample"]["md5"] = report.hashes.md5;
            doc["sample"]["sha1"] = report.hashes.sha1;
            doc["sample"]["sha256"] = report.hashes.sha256;

            for (const ImportRecord& sampleImport : report.imports) {
                doc["file"]["imports"].push_back({ {"dll", sampleImport.dll}, {"name", sampleImport.name}, {"va", sampleImport.va} });
            }

            for (const ExportRecord& sampleExport : report.exports) {
                doc["file"]["exports"].push_back({ {"name", sampleExport.name}, {"va", sampleExport.va} });
            }

            for (const SectionRecord& sampleSection : report.sections) {
                doc["file"]["sections"].push_back({ {"name", sampleSection.name}, {"va", sampleSection.va} });
            }

            doc["file"]["strings"] = report.strings;

            json process;
            process["pid"] = report.process.pid;
            process["ppid"] = report.process.ppid;
            process["name"] = report.process.name;
            process["environ"] = report.process.env_strings;
            process["threads"] = report.process.threads;
            process["calls"] = std::move(calls);

            doc["processes"].push_back(std::move(process));
            return doc;
        }

        // Recovered guest memory can always surprise us with a byte sequence that
        // isn't valid UTF-8. Substituting it beats throwing away an entire trace's
        // worth of extraction over one bad string.
        std::string dumpCompact(const nlohmann::json& value) {
            return value.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        }

        // Stands in for the calls array while the rest of the document is serialized. The
        // 0x01 bytes are what make it safe: nlohmann escapes every control character, so a
        // call argument holding this text verbatim still serializes to something else --
        // and the uniqueness check below covers the case where somehow it does not.
        constexpr char kCallsSentinel[] = "\x01ttdcapa:calls\x01";
    }

    std::string renderReport(const Report& report) {
        using json = nlohmann::json;
        json calls = json::array();
        for (const CallRecord& callRecord : report.process.calls) {
            calls.push_back(renderCall(callRecord));
        }
        return dumpCompact(renderSkeleton(report, std::move(calls)));
    }

    bool writeReportStream(const Report& report, std::filesystem::path outputFilePath) {
        // renderReport builds a DOM of the whole report and then a string of the whole
        // report, both while report.process.calls is still live -- three copies of the
        // largest thing this tool produces, at the one moment it can least afford them. A
        // trace with millions of calls dies here and nowhere else.
        //
        // So serialize everything *except* the calls, and stream those into the gap one at
        // a time. Peak drops to the report-minus-calls plus a single call object. The bytes
        // are unchanged: the skeleton is the same nlohmann document dumped with the same
        // arguments, and each call comes from the same renderCall the DOM path uses.
        const std::string skeleton = dumpCompact(renderSkeleton(report, kCallsSentinel));

        // Ask nlohmann what it made of the sentinel rather than hand-writing the escape, so
        // this cannot drift from however the serializer chooses to render a control byte.
        const std::string needle = dumpCompact(nlohmann::json(kCallsSentinel));
        const size_t at = skeleton.find(needle);
        if (at == std::string::npos || skeleton.find(needle, at + needle.size()) != std::string::npos) {
            // Either the serializer rendered it differently than expected, or something in
            // the trace reproduced it exactly. Neither should happen, and both are
            // recoverable by taking the path that needs no splice at all.
            log::err() << "[!] Report sentinel was not unique; writing the report unstreamed\n";
            std::ofstream fallbackFile(outputFilePath, std::ios::binary);
            if (!fallbackFile.is_open()) return false;
            fallbackFile << renderReport(report) << "\n";
            return fallbackFile.good();
        }

        std::ofstream reportFile(outputFilePath, std::ios::binary);
        if (!reportFile.is_open()) {
            return false;
        }

        reportFile.write(skeleton.data(), static_cast<std::streamsize>(at));
        reportFile << "[";
        bool first = true;
        for (const CallRecord& callRecord : report.process.calls) {
            if (!first) reportFile << ",";
            first = false;
            reportFile << dumpCompact(renderCall(callRecord));
        }
        reportFile << "]";
        reportFile.write(skeleton.data() + at + needle.size(),
                         static_cast<std::streamsize>(skeleton.size() - at - needle.size()));
        reportFile << "\n";
        return reportFile.good();
    }

    bool writeReport(const Report& report, std::filesystem::path outputFilePath) {
        // This progress line is assembled from fragments, so every fragment has to go to the
        // same stream -- the two buffer separately, and a line split across them would arrive
        // as two messages. All three pieces are narration, so they go to dbg() together; the
        // failure below is a real error and is written to err() as a line of its own rather
        // than tacked onto the end of this one.
        ttdcapa::log::dbg() << "[+] Generating JSON report...";

        // Streamed rather than rendered whole: see writeReportStream. The bytes are the
        // same either way; the difference is whether a trace with millions of calls has to
        // hold three copies of its own report to write one.
        if (!writeReportStream(report, outputFilePath)) {
            ttdcapa::log::dbg() << "ERROR!\n";
            ttdcapa::log::err() << "[-] Unable to write report JSON!\n";
            return false;
        }

        ttdcapa::log::dbg() << "DONE!\n";
        return true;
    }
}
