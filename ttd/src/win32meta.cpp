#include "win32meta.hpp"
#include "builtinsigs.hpp"
#include "log.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>

namespace ttdcapa::win32meta {
    namespace {
        constexpr char kMagic[8] = { 'W', '3', '2', 'I', 'D', 'X', '0', '1' };
        constexpr uint32_t kFormatVersion = 1;

        // Record sizes must match the struct.pack formats in tools/build-win32-index.py.
        constexpr size_t kHeaderSize = 32;
        constexpr size_t kFuncRecSize = 16;
        constexpr size_t kParamRecSize = 24;
        constexpr size_t kEnumRecSize = 16;
        constexpr size_t kEnumValRecSize = 16;

        template <typename T>
        T readAt(const uint8_t* p, size_t off) {
            T v{};
            std::memcpy(&v, p + off, sizeof(T));
            return v;
        }

        int popcount64(uint64_t v) {
            int n = 0;
            while (v) {
                v &= v - 1;
                ++n;
            }
            return n;
        }
    }  // namespace

    bool Index::parseBlob(const std::filesystem::path& path, std::vector<Staged>& out,
                          bool withEnums, std::string& error) {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            error = "cannot open index";
            return false;
        }
        std::vector<uint8_t> blob((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (blob.size() < kHeaderSize || std::memcmp(blob.data(), kMagic, sizeof(kMagic)) != 0) {
            error = "not a win32 index file (bad magic)";
            return false;
        }

        const uint8_t* p = blob.data();
        uint32_t version = readAt<uint32_t>(p, 8);
        if (version != kFormatVersion) {
            error = "index format version " + std::to_string(version) +
                    ", expected " + std::to_string(kFormatVersion) + " (regenerate with tools/build-win32-index.py)";
            return false;
        }

        uint32_t funcCount = readAt<uint32_t>(p, 12);
        uint32_t paramCount = readAt<uint32_t>(p, 16);
        uint32_t enumCount = readAt<uint32_t>(p, 20);
        uint32_t enumValCount = readAt<uint32_t>(p, 24);
        uint32_t strtabSize = readAt<uint32_t>(p, 28);

        size_t funcOff = kHeaderSize;
        size_t paramOff = funcOff + static_cast<size_t>(funcCount) * kFuncRecSize;
        size_t enumOff = paramOff + static_cast<size_t>(paramCount) * kParamRecSize;
        size_t enumValOff = enumOff + static_cast<size_t>(enumCount) * kEnumRecSize;
        size_t strOff = enumValOff + static_cast<size_t>(enumValCount) * kEnumValRecSize;
        if (strOff + strtabSize != blob.size()) {
            error = "index is truncated or corrupt";
            return false;
        }
        // Every string offset is dereferenced without a bounds check below, so the
        // pool must be NUL-terminated for that to be safe.
        if (strtabSize == 0 || blob[blob.size() - 1] != 0) {
            error = "index string pool is not NUL-terminated";
            return false;
        }

        // The strings stay borrowed from here for the life of the index.
        blobs_.push_back(std::move(blob));
        p = blobs_.back().data();
        const char* strtab = reinterpret_cast<const char*>(p + strOff);
        auto str = [&](uint32_t off) -> const char* {
            return off < strtabSize ? strtab + off : "";
        };

        // Enum tables are appended, so a later source's indices are shifted past the
        // ones already loaded. Only the primary carries any today, but the offset
        // costs nothing and stops a second table-bearing source being silently wrong.
        uint32_t enumBase = static_cast<uint32_t>(enums_.size());
        if (withEnums && enumCount != 0) {
            uint32_t valueBase = static_cast<uint32_t>(enumValues_.size());
            for (uint32_t i = 0; i < enumValCount; ++i) {
                size_t o = enumValOff + static_cast<size_t>(i) * kEnumValRecSize;
                EnumValue ev;
                ev.name = str(readAt<uint32_t>(p, o));
                ev.value = readAt<int64_t>(p, o + 8);
                enumValues_.push_back(ev);
            }
            for (uint32_t i = 0; i < enumCount; ++i) {
                size_t o = enumOff + static_cast<size_t>(i) * kEnumRecSize;
                EnumTable et;
                et.name = str(readAt<uint32_t>(p, o));
                et.valueOffset = valueBase + readAt<uint32_t>(p, o + 4);
                et.valueCount = readAt<uint32_t>(p, o + 8);
                et.isFlags = p[o + 12] != 0;
                et.width = p[o + 13];
                if (static_cast<size_t>(et.valueOffset) + et.valueCount > enumValues_.size()) {
                    et.valueOffset = 0;
                    et.valueCount = 0;
                }
                enums_.push_back(et);
            }
        }

        std::vector<ParamSig> params(paramCount);
        for (uint32_t i = 0; i < paramCount; ++i) {
            size_t o = paramOff + static_cast<size_t>(i) * kParamRecSize;
            ParamSig& ps = params[i];
            ps.name = str(readAt<uint32_t>(p, o));
            ps.type = str(readAt<uint32_t>(p, o + 4));
            ps.kind = static_cast<ArgKind>(p[o + 8]);
            ps.attrs = p[o + 9];
            ps.slot = p[o + 10];
            ps.auxKind = static_cast<AuxKind>(p[o + 11]);
            ps.auxValue = readAt<int32_t>(p, o + 12);
            ps.enumIndex = readAt<uint32_t>(p, o + 16);
            ps.pointeeSize = readAt<uint16_t>(p, o + 20);
            ps.x86Footprint = p[o + 22];
            if (ps.enumIndex != 0xFFFFFFFFu) {
                ps.enumIndex = withEnums && ps.enumIndex < enumCount
                    ? enumBase + ps.enumIndex
                    : 0xFFFFFFFFu;
            }
        }

        for (uint32_t i = 0; i < funcCount; ++i) {
            size_t o = funcOff + static_cast<size_t>(i) * kFuncRecSize;
            uint32_t firstParam = readAt<uint32_t>(p, o + 8);
            uint8_t count = p[o + 12];
            if (static_cast<size_t>(firstParam) + count > params.size()) {
                error = "index parameter range out of bounds";
                return false;
            }
            Staged st;
            st.name = str(readAt<uint32_t>(p, o));
            st.dll = str(readAt<uint32_t>(p, o + 4));
            st.flags = p[o + 13];
            st.params.assign(params.begin() + firstParam, params.begin() + firstParam + count);
            out.push_back(std::move(st));
        }
        return true;
    }

    bool Index::load(const std::filesystem::path& path,
                     const std::vector<std::filesystem::path>& overlays,
                     std::string& error) {
        blobs_.clear();
        funcs_.clear();
        params_.clear();
        enums_.clear();
        enumValues_.clear();
        byName_.clear();

        std::vector<Staged> staged;
        if (!parseBlob(path, staged, /*withEnums=*/true, error)) {
            return false;
        }

        // Everything after the primary fills gaps only. An index built from real
        // metadata is richer than one recovered from headers or written by hand, so
        // it wins wherever it has an answer -- but an entry it flagged unsupported is
        // no answer at all, and gets replaced.
        std::unordered_map<std::string_view, size_t> seen;
        seen.reserve(staged.size() * 2);
        for (size_t i = 0; i < staged.size(); ++i) {
            seen.emplace(std::string_view(staged[i].name), i);
        }

        auto absorb = [&](std::vector<Staged>& incoming) {
            for (Staged& st : incoming) {
                auto it = seen.find(std::string_view(st.name));
                if (it == seen.end()) {
                    seen.emplace(std::string_view(st.name), staged.size());
                    staged.push_back(std::move(st));
                } else if (staged[it->second].flags & FlagUnsupported) {
                    staged[it->second] = std::move(st);
                }
            }
        };

        for (const std::filesystem::path& overlay : overlays) {
            std::vector<Staged> extra;
            std::string overlayError;
            // An overlay is optional by design: a missing or unreadable one costs
            // coverage, not correctness, so it must not fail the whole load.
            if (!parseBlob(overlay, extra, /*withEnums=*/false, overlayError)) {
                log::err() << "[!] ignoring " << overlay.filename().string() << ": "
                           << overlayError << "\n";
                continue;
            }
            absorb(extra);
        }

        mergeBuiltins(staged);
        finalize(staged);
        path_ = path;
        return true;
    }

    void Index::finalize(std::vector<Staged>& staged) {
        size_t total = 0;
        for (const Staged& st : staged) {
            total += st.params.size();
        }
        // One contiguous array, built once. FuncSig::params points into it, so it must
        // never grow again -- which is why every source is staged before this runs.
        params_.reserve(total);
        funcs_.reserve(staged.size());
        byName_.reserve(staged.size() * 2);

        for (Staged& st : staged) {
            size_t first = params_.size();
            params_.insert(params_.end(), st.params.begin(), st.params.end());
            FuncSig fs;
            fs.name = st.name;
            fs.dll = st.dll;
            fs.paramCount = static_cast<uint8_t>(st.params.size());
            fs.flags = st.flags;
            fs.params = st.params.empty() ? nullptr : &params_[first];
            byName_[std::string_view(fs.name)] = static_cast<uint32_t>(funcs_.size());
            funcs_.push_back(fs);
        }
    }

    uint32_t Index::findEnum(const char* name) const {
        for (size_t i = 0; i < enums_.size(); ++i) {
            if (std::strcmp(enums_[i].name, name) == 0) {
                return static_cast<uint32_t>(i);
            }
        }
        return 0xFFFFFFFFu;  // the generator never referenced it; render the number
    }

    void Index::mergeBuiltins(std::vector<Staged>& staged) {
        std::unordered_map<std::string_view, size_t> byName;
        byName.reserve(staged.size() * 2);
        for (size_t i = 0; i < staged.size(); ++i) {
            byName.emplace(std::string_view(staged[i].name), i);
        }

        for (const BuiltinFunc& bf : builtinSignatures()) {
            auto it = byName.find(std::string_view(bf.name));
            if (it != byName.end() && !(staged[it->second].flags & FlagUnsupported)) {
                continue;  // a generated signature already covers it
            }
            Staged st;
            st.name = bf.name;
            st.dll = bf.dll;
            st.flags = 0;
            st.params.resize(bf.paramCount);
            for (uint8_t i = 0; i < bf.paramCount; ++i) {
                const BuiltinParam& src = bf.params[i];
                ParamSig& ps = st.params[i];
                ps.name = src.name;
                ps.type = src.type;
                ps.kind = src.kind;
                ps.attrs = src.attrs;
                ps.slot = i;  // none of these returns an aggregate needing a hidden pointer
                ps.auxKind = src.auxKind;
                ps.auxValue = src.auxValue;
                ps.pointeeSize = src.pointeeSize;
                ps.x86Footprint = src.x86Footprint;
                ps.enumIndex = 0xFFFFFFFFu;
            }
            if (it != byName.end()) {
                staged[it->second] = std::move(st);
            } else {
                byName.emplace(std::string_view(st.name), staged.size());
                staged.push_back(std::move(st));
            }
        }

        // The flag-enum overlay. phnt types every flag argument as a bare ULONG, so
        // the tables that name those bits live only in win32json's half of the index;
        // this is the one place the two sources are stitched together. Kept as a
        // hand-written list because it is a judgement about meaning, not a fact any
        // header states.
        for (const EnumOverlay& ov : builtinEnumOverlays()) {
            auto it = byName.find(std::string_view(ov.function));
            if (it == byName.end()) {
                continue;
            }
            uint32_t idx = findEnum(ov.enumName);
            if (idx == 0xFFFFFFFFu) {
                continue;  // win32json never referenced that enum; render the number
            }
            for (ParamSig& ps : staged[it->second].params) {
                if (std::strcmp(ps.name, ov.parameter) != 0) {
                    continue;
                }
                ps.enumIndex = idx;
                // A scalar the enum describes directly becomes an Enum; a pointer to
                // one keeps its pointer kind, and utils.cpp decodes the pointee.
                if (ps.kind == ArgKind::Integer) {
                    ps.kind = ArgKind::Enum;
                }
            }
        }
    }

    const FuncSig* Index::lookup(std::string_view api) const {
        auto it = byName_.find(api);
        return it == byName_.end() ? nullptr : &funcs_[it->second];
    }

    const char* Index::enumName(uint32_t enumIndex) const {
        return enumIndex < enums_.size() ? enums_[enumIndex].name : "";
    }

    std::vector<std::string> Index::decodeEnum(uint32_t enumIndex, uint64_t value) const {
        std::vector<std::string> out;
        if (enumIndex >= enums_.size()) {
            return out;
        }
        const EnumTable& et = enums_[enumIndex];
        // The captured value is a full 64-bit register; mask to the enum's real width
        // so sign-extension and upper garbage don't defeat the comparisons.
        uint64_t mask = et.width >= 8 ? ~0ull : ((1ull << (et.width * 8)) - 1);
        uint64_t v = value & mask;

        const EnumValue* vals = enumValues_.data() + et.valueOffset;
        for (uint32_t i = 0; i < et.valueCount; ++i) {
            if ((static_cast<uint64_t>(vals[i].value) & mask) == v) {
                out.emplace_back(vals[i].name);
                return out;  // exact match wins, flags or not
            }
        }
        if (!et.isFlags || v == 0) {
            return out;
        }

        // Greedy decomposition: consume the widest matching bit groups first so
        // composites like GENERIC_WRITE beat their individual constituent bits.
        std::vector<uint32_t> order(et.valueCount);
        for (uint32_t i = 0; i < et.valueCount; ++i) {
            order[i] = i;
        }
        std::sort(order.begin(), order.end(), [&](uint32_t a, uint32_t b) {
            return popcount64(static_cast<uint64_t>(vals[a].value) & mask) >
                   popcount64(static_cast<uint64_t>(vals[b].value) & mask);
        });

        uint64_t remaining = v;
        for (uint32_t i : order) {
            uint64_t bits = static_cast<uint64_t>(vals[i].value) & mask;
            if (bits != 0 && (remaining & bits) == bits) {
                out.emplace_back(vals[i].name);
                remaining &= ~bits;
            }
        }
        if (remaining != 0) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "0x%llx", static_cast<unsigned long long>(remaining));
            out.emplace_back(buf);
        }
        return out;
    }

    Index& index() {
        static Index instance;
        return instance;
    }

    namespace {
        std::filesystem::path executableDir() {
            wchar_t buf[MAX_PATH * 4];
            DWORD n = ::GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
            if (n == 0 || n >= std::size(buf)) {
                return {};
            }
            return std::filesystem::path(buf, buf + n).parent_path();
        }
    }  // namespace

    bool loadIndex(const std::filesystem::path& explicitPath, std::string& error) {
        std::vector<std::filesystem::path> candidates;
        if (!explicitPath.empty()) {
            candidates.push_back(explicitPath);
        } else {
            std::filesystem::path dir = executableDir();
            if (!dir.empty()) {
                candidates.push_back(dir / L"win32-index.bin");
                // running straight out of ttd\bin\<plat>\<config>\ during development
                candidates.push_back(dir / L".." / L".." / L".." / L"data" / L"win32-index.bin");
            }
        }

        std::error_code ec;
        for (const auto& c : candidates) {
            if (!std::filesystem::exists(c, ec)) {
                continue;
            }
            // The native-API overlay lives beside the primary. It is optional: without
            // it every ntdll call goes back to being unsignatured, which is a loss of
            // coverage rather than a failure.
            std::vector<std::filesystem::path> overlays;
            std::filesystem::path phnt = c.parent_path() / L"phnt-index.bin";
            if (std::filesystem::exists(phnt, ec)) {
                overlays.push_back(phnt);
            }
            if (index().load(c, overlays, error)) {
                return true;
            }
            return false;  // found but unusable: surface the real reason
        }
        error = "win32-index.bin not found (run tools/build-win32-index.py, or pass --win32-index)";
        return false;
    }

    const char* kindName(ArgKind kind) {
        switch (kind) {
            case ArgKind::Integer:         return "int";
            case ArgKind::Bool:            return "bool";
            case ArgKind::Handle:          return "handle";
            case ArgKind::Enum:            return "enum";
            case ArgKind::Float:           return "float";
            case ArgKind::Double:          return "double";
            case ArgKind::AnsiString:      return "str";
            case ArgKind::WideString:      return "wstr";
            case ArgKind::AnsiBuffer:      return "strbuf";
            case ArgKind::WideBuffer:      return "wstrbuf";
            case ArgKind::ByteBuffer:      return "buf";
            case ArgKind::PtrToInt:        return "int*";
            case ArgKind::StructPtr:       return "struct*";
            case ArgKind::FuncPtr:         return "fnptr";
            case ArgKind::Guid:            return "guid";
            case ArgKind::Pointer:         return "ptr";
            case ArgKind::PtrToAnsiString: return "str*";
            case ArgKind::PtrToWideString: return "wstr*";
            case ArgKind::CountedAnsiString: return "astr";
            case ArgKind::CountedWideString: return "ustr";
            case ArgKind::Unknown:
            default:                       return "unknown";
        }
    }
}  // namespace ttdcapa::win32meta
