#include "ttdutils.hpp"
#include "utils.hpp"
#include "ttd_pe_utils.hpp"

#include <cstdint>
#include <iostream>
#include <format>
#include <string>
#include <optional>
#include <winerror.h>
#include <unordered_map>
#include <map>
#include <ranges>

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

namespace ttdcapa {
    std::unordered_map<uint64_t, ResolvedExport> resolveTraceModuleExports(TTD::Replay::UniqueReplayEngine& engine, TTD::Replay::UniqueCursor& cursor) {
        std::unordered_map<uint64_t, ResolvedExport> resolvedTraceModuleExports;  // function VA -> resolved target

        size_t count = engine->GetModuleLoadedEventCount();
        TTD::Replay::ModuleLoadedEvent const* moduleLoadEvents = engine->GetModuleLoadedEventList();
        cursor->SetPosition(engine->GetFirstPosition());

        for (size_t i = 0; i < count; i++) {
            TTD::Replay::ModuleLoadedEvent const& moduleLoadEvent = moduleLoadEvents[i];

            // std::wcout << std::format(L"[+] Found module: {}\n", moduleLoadEvent.pModule->pName);
            cursor->SetPosition(moduleLoadEvent.Position);

            // walk module exports
            std::wstring moduleName(moduleLoadEvent.pModule->pName, moduleLoadEvent.pModule->NameLength);
            std::string moduleBaseName = getModuleBaseName(moduleName);
            std::wstring moduleNameStripped(moduleBaseName.begin(), moduleBaseName.end());

            std::vector<std::pair<uint64_t, std::string>> moduleExports;
            bool is64 = true;
            if (getModuleExports(&cursor, moduleLoadEvent.pModule->Address, moduleExports, &is64)) {
                for (auto& moduleExport : moduleExports) {
                    ResolvedExport resolved;
                    resolved.module = moduleNameStripped;
                    resolved.api = std::move(moduleExport.second);
                    resolved.is64 = is64;
                    resolvedTraceModuleExports.emplace(moduleExport.first, std::move(resolved));
                }
            }
        }

        return resolvedTraceModuleExports;
    }

    std::string convertWstringToString(const std::wstring& ws) {
        if (ws.empty()) {
            return {};
        }
        int needed = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) {
            return {};
        }
        std::string out(static_cast<size_t>(needed), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), needed, nullptr, nullptr);
        return out;
    }

    size_t readMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, void* dest, unsigned __int64 size) {
        TTD::Replay::MemoryBuffer memoryBuffer = cursor->get()->QueryMemoryBuffer(addr, TTD::BufferView{ dest, size });
        return memoryBuffer.Memory.Size;
    }

    bool buildTraceIndex(TTD::Replay::UniqueReplayEngine& engine, bool rebuildUnloadableIndex) {
        if (engine->GetIndexStatus() == TTD::Replay::IndexStatus::IndexFileLoaded) {
            ttdcapa::log::dbg() << "[+] Trace index already built!\n";
            return true;
        }

        // One whole line per message, and never a flushed partial one. log.cpp buffers until a
        // newline before handing anything to the sink, so flushing a trailing "..." delivers it
        // as a message in its own right, and the "Done!" meant to land on the end of it arrives
        // as a second one carrying no [+]/[!]/[-] tag -- which means levelOf() cannot classify
        // it either. The console-progress idiom only works on a console; a host holding the sink
        // callback gets two messages, one of them untagged.
        ttdcapa::log::dbg() << "[+] Building trace index (first run may be slow)...\n";
        auto progressCallback = [](void const*, TTD::Replay::IndexBuildProgressType const*) {};  // unused

        TTD::Replay::IndexBuildFlags const flags = rebuildUnloadableIndex
            ? TTD::Replay::IndexBuildFlags::DeleteExistingUnloadableIndexFile
            : TTD::Replay::IndexBuildFlags::None;

        TTD::Replay::IndexStatus const status = engine->BuildIndex(progressCallback, nullptr, flags);
        if (status == TTD::Replay::IndexStatus::IndexFileLoaded) {
            ttdcapa::log::dbg() << "[+] Trace index built\n";
            return true;
        }

        ttdcapa::log::err() << std::format(
            "[!] Index build did not complete (Status: {}). Memory accesses will be "
            "significantly slower, and out-params the kernel wrote may not be recoverable!\n",
            convertWstringToString(TTD::Replay::GetIndexStatusName(status))
        );

        // An index exists but is unusable (stale or corrupt), which is repairable
        if (status == TTD::Replay::IndexStatus::IndexFileUnloadable && !rebuildUnloadableIndex) {
            ttdcapa::log::err() << "[!] Re-run with index rebuilding enabled to delete the unusable "
                                   ".idx file and build a fresh one.\n";
        }
        return false;
    }

    bool initializeTTDEngine(TTD::Replay::UniqueReplayEngine& engine, std::wstring traceFilePath,
                             bool rebuildUnloadableIndex) {
        // The engine holds this pointer for its whole lifetime and calls into it
        // whenever it reports an error. A stack local would dangle the moment this
        // function returns, and the first derailment during ReplayForward would then
        // dispatch a virtual call through reclaimed stack memory.
        static ConsoleErrorReporting reporter;
        engine->RegisterDebugModeAndLogging(TTD::Replay::DebugModeType::None, &reporter);

        if (!engine->Initialize(traceFilePath.c_str())) {
            ttdcapa::log::werr() << L"[-] Failed to open trace: " << traceFilePath.c_str() << std::endl;
            return false;
        }

        buildTraceIndex(engine, rebuildUnloadableIndex);

        ttdcapa::log::dbg() << "[+] Initialized TTD engine\n";
        return true;
    }

    namespace {
        bool isPlausibleTextByte(unsigned char c) {
            return c == '\t' || c == '\r' || c == '\n' || (c >= 0x20 && c != 0x7f);
        }

        // The -A entry points take strings in the ANSI code page, so their high
        // bytes are not UTF-8. Emitting them raw would produce a report that the
        // JSON serializer refuses to write, so transcode before anything else sees
        // them. Pure-ASCII input (the overwhelming majority) short-circuits.
        std::string ansiToUtf8(std::string bytes) {
            bool ascii = true;
            for (unsigned char c : bytes) {
                if (c >= 0x80) {
                    ascii = false;
                    break;
                }
            }
            if (ascii) {
                return bytes;
            }

            int wide = ::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), nullptr, 0);
            if (wide > 0) {
                std::wstring ws(static_cast<size_t>(wide), L'\0');
                if (::MultiByteToWideChar(CP_ACP, 0, bytes.data(), static_cast<int>(bytes.size()), ws.data(), wide) == wide) {
                    return convertWstringToString(ws);
                }
            }

            // Unconvertible: keep the ASCII skeleton rather than dropping the string.
            for (char& c : bytes) {
                if (static_cast<unsigned char>(c) >= 0x80) {
                    c = '?';
                }
            }
            return bytes;
        }
    }  // namespace

    // QueryMemoryBuffer answers from a *single* contiguous recorded range
    // (IReplayEngine.h:1510: "a single range of contiguous memory bytes stored
    // internally"), so a short return means "this recorded range ended here",
    // not "nothing further was recorded". A string the guest touched in two
    // pieces -- exactly what the loader's own name compares do -- lands in two
    // ranges, and a single query stops at the seam. Re-query from the seam until
    // the buffer is full or a query genuinely comes back empty; that empty result
    // is what makes this terminate.
    //
    // Do not reach for a debugger's memory read to check this: WinDbg can fall
    // back to the image on disk and will happily show bytes the trace never
    // recorded. Only the replay API's answer is the truth here.
    size_t MemorySource::query(uint64_t addr, void* dst, size_t size) const {
        if (cursor != nullptr) {
            return cursor->QueryMemoryBuffer(TTD::GuestAddress{ addr },
                                             TTD::BufferView{ dst, size }, policy).Memory.Size;
        }
        return thread->QueryMemoryBuffer(TTD::GuestAddress{ addr },
                                         TTD::BufferView{ dst, size }).Memory.Size;
    }

    size_t readRecordedRun(MemorySource const& src, uint64_t addr,
                           void* dst, size_t size) {
        auto* out = static_cast<uint8_t*>(dst);
        size_t filled = 0;
        while (filled < size) {
            size_t got = src.query(addr + filled, out + filled, size - filled);
            if (got == 0 || got > size - filled) {
                break;
            }
            filled += got;
        }
        return filled;
    }

    // Try to interpret the bytes at `addr` as a NUL-terminated ASCII or UTF-16LE
    // string. Returns the decoded ASCII text if it looks like a real string.
    std::optional<std::string> tryReadString(MemorySource const& src, uint64_t addr,
                                             bool* truncated) {
        if (truncated) {
            *truncated = false;
        }
        if (addr < kMinStringAddr) {
            return std::nullopt;  // null / low addresses are never string pointers
        }

        constexpr size_t kMax = 512;
        char buf[kMax];
        size_t avail = readRecordedRun(src, addr, buf, kMax);
        if (avail < 2) {
            return std::nullopt;
        }

        // ASCII: printable run terminated by NUL.
        {
            std::string s;
            bool terminated = false;
            for (size_t i = 0; i < avail; ++i) {
                unsigned char c = static_cast<unsigned char>(buf[i]);
                if (c == 0) {
                    terminated = true;
                    break;
                }
                if (c == '\t' || (c >= 0x20 && c <= 0x7e)) {
                    s.push_back(static_cast<char>(c));
                }
                else {
                    s.clear();
                    break;
                }
            }
            if (s.size() >= 4) {
                if (truncated) {
                    *truncated = !terminated;
                }
                return s;
            }
        }

        // UTF-16LE: printable ASCII chars each followed by 0x00, terminated by 0x0000.
        {
            std::string s;
            bool ok = true;
            bool terminated = false;
            for (size_t i = 0; i + 1 < avail; i += 2) {
                unsigned char lo = static_cast<unsigned char>(buf[i]);
                unsigned char hi = static_cast<unsigned char>(buf[i + 1]);
                if (lo == 0 && hi == 0) {
                    terminated = true;
                    break;
                }
                if (hi == 0 && (lo == '\t' || (lo >= 0x20 && lo <= 0x7e))) {
                    s.push_back(static_cast<char>(lo));
                }
                else {
                    ok = false;
                    break;
                }
            }
            if (ok && s.size() >= 4) {
                if (truncated) {
                    *truncated = !terminated;
                }
                return s;
            }
        }
        return std::nullopt;
    }

    std::optional<std::string> readAnsiString(MemorySource const& src, uint64_t addr,
                                              size_t maxChars, bool* truncated) {
        if (truncated) {
            *truncated = false;
        }
        if (addr < kMinStringAddr) {
            return std::nullopt;
        }

        std::string s;
        char chunk[256];
        while (s.size() < maxChars) {
            size_t want = (std::min)(sizeof(chunk), maxChars - s.size());
            size_t avail = readRecordedRun(src, addr + s.size(), chunk, want);
            if (avail == 0) {
                break;  // nothing further was recorded here
            }
            for (size_t i = 0; i < avail; ++i) {
                unsigned char c = static_cast<unsigned char>(chunk[i]);
                if (c == 0) {
                    return ansiToUtf8(std::move(s));  // complete: terminator found
                }
                if (!isPlausibleTextByte(c)) {
                    return std::nullopt;  // control bytes mean this wasn't a string after all
                }
                s.push_back(static_cast<char>(c));
            }
        }
        // Ran out of recorded memory (or hit maxChars) before the terminator. Keep
        // what we have -- it looked like text the whole way -- but say so, because a
        // reader shown 'WakeAllC' cannot otherwise tell it from a whole export name.
        if (s.empty()) {
            return std::nullopt;
        }
        if (truncated) {
            *truncated = true;
        }
        return ansiToUtf8(std::move(s));
    }

    std::optional<std::string> readWideString(MemorySource const& src, uint64_t addr,
                                              size_t maxChars, bool* truncated) {
        if (truncated) {
            *truncated = false;
        }
        if (addr < kMinStringAddr) {
            return std::nullopt;
        }

        std::wstring s;
        wchar_t chunk[128];
        while (s.size() < maxChars) {
            size_t wantChars = (std::min)(std::size(chunk), maxChars - s.size());
            size_t got = readRecordedRun(src, addr + s.size() * sizeof(wchar_t),
                                         chunk, wantChars * sizeof(wchar_t));
            size_t availChars = got / sizeof(wchar_t);
            if (availChars == 0) {
                break;
            }
            for (size_t i = 0; i < availChars; ++i) {
                wchar_t wc = chunk[i];
                if (wc == L'\0') {
                    return convertWstringToString(s);  // complete, empty string included
                }
                // Reject C0 controls (other than the usual whitespace) rather than
                // emitting mojibake for a pointer that only looked like a string.
                if (wc < 0x20 && wc != L'\t' && wc != L'\r' && wc != L'\n') {
                    return std::nullopt;
                }
                s.push_back(wc);
            }
            if (got % sizeof(wchar_t) != 0) {
                break;  // the recorded range ended mid-character
            }
        }
        if (s.empty()) {
            return std::nullopt;
        }
        if (truncated) {
            *truncated = true;
        }
        return convertWstringToString(s);
    }

    std::optional<std::string> readAnsiChars(MemorySource const& src, uint64_t addr,
                                             size_t count, bool* truncated) {
        if (truncated) {
            *truncated = false;
        }
        if (addr < kMinStringAddr || count == 0) {
            return std::nullopt;
        }
        std::vector<char> buf(count);
        size_t got = readRecordedRun(src, addr, buf.data(), count);
        if (got == 0) {
            return std::nullopt;
        }
        std::string s;
        bool terminated = false;
        for (size_t i = 0; i < got; ++i) {
            unsigned char c = static_cast<unsigned char>(buf[i]);
            if (c == 0) {
                terminated = true;  // a counted string may still be NUL-terminated
                break;
            }
            if (!isPlausibleTextByte(c)) {
                return std::nullopt;
            }
            s.push_back(static_cast<char>(c));
        }
        // Short of the stated length is only truncation if we did not reach a
        // terminator first: a descriptor whose length covers trailing padding still
        // yields the whole string, and marking that incomplete would withhold a
        // complete value from the matcher.
        if (truncated) {
            *truncated = !terminated && got < count;
        }
        return ansiToUtf8(std::move(s));
    }

    std::optional<std::string> readWideChars(MemorySource const& src, uint64_t addr,
                                             size_t count, bool* truncated) {
        if (truncated) {
            *truncated = false;
        }
        if (addr < kMinStringAddr || count == 0) {
            return std::nullopt;
        }
        std::vector<wchar_t> buf(count);
        size_t got = readRecordedRun(src, addr, buf.data(), count * sizeof(wchar_t));
        size_t availChars = got / sizeof(wchar_t);
        if (availChars == 0) {
            return std::nullopt;
        }
        std::wstring s;
        bool terminated = false;
        for (size_t i = 0; i < availChars; ++i) {
            wchar_t wc = buf[i];
            if (wc == L'\0') {
                terminated = true;
                break;
            }
            if (wc < 0x20 && wc != L'\t' && wc != L'\r' && wc != L'\n') {
                return std::nullopt;
            }
            s.push_back(wc);
        }
        if (truncated) {
            *truncated = !terminated && availChars < count;
        }
        return convertWstringToString(s);
    }

    // Capture one candidate argument: a dereferenced string if it points to one, otherwise the raw integer value.
    ttdcapa::ArgValue captureCallArg(MemorySource const& src, uint64_t value) {
        if (auto s = tryReadString(src, value)) {
            return *s;
        }
        return static_cast<int64_t>(value);
    }
}