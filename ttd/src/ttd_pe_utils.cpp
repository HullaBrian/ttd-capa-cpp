#include "ttd_pe_utils.hpp"
#include "ttdutils.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <TTD/IdnaBasicTypes.h>
#include <TTD/IReplayEngineStl.h>

namespace ttdcapa {
namespace {

// Read a NUL-terminated ASCII string at a guest address (bounded).
std::string readCSTR(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress addr, size_t maxLength = 512) {
    std::string s;
    s.reserve(64);
    char chunk[64];
    while (s.size() < maxLength) {
        size_t want = sizeof(chunk);
        size_t got = readMemory(cursor, addr + s.size(), chunk, want);
        if (got == 0) {
            break;
        }
        for (size_t i = 0; i < got; ++i) {
            if (chunk[i] == '\0') {
                return s;
            }
            s.push_back(chunk[i]);
        }
        if (got < want) {
            break;
        }
    }
    return s;
}

// The signature and IMAGE_FILE_HEADER that precede the optional header are identical
// in PE32 and PE32+, so the offset of the optional header is the same in both.
constexpr uint32_t kOptionalHeaderOffset = offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
static_assert(kOptionalHeaderOffset == offsetof(IMAGE_NT_HEADERS32, OptionalHeader),
              "PE32 and PE32+ must agree on where the optional header starts");

// Just the parts of an image's headers the parsers below need, read in a way that
// works for both PE32 and PE32+.
struct PeHeaders {
    bool is64 = false;
    uint16_t machine = 0;   // IMAGE_FILE_MACHINE_*
    uint32_t ntOffset = 0;  // e_lfanew
    uint16_t numberOfSections = 0;
    uint16_t sizeOfOptionalHeader = 0;
    IMAGE_DATA_DIRECTORY dataDir[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};

    // Width of a thunk/pointer in this image.
    uint32_t pointerSize() const { return is64 ? 8u : 4u; }

    // The section table follows the optional header, whose size varies by format.
    uint32_t sectionTableOffset() const { return ntOffset + kOptionalHeaderOffset + sizeOfOptionalHeader; }
};

// Locate and validate the headers of the image at `base`, for either PE format.
bool readNTHeaders(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, PeHeaders& pe) {
    IMAGE_DOS_HEADER dos{};
    if (!readMemory(cursor, moduleBaseAddress, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }
    pe.ntOffset = static_cast<uint32_t>(dos.e_lfanew);

    struct {
        uint32_t Signature;
        IMAGE_FILE_HEADER FileHeader;
    } head{};
    if (!readMemory(cursor, moduleBaseAddress + pe.ntOffset, &head, sizeof(head))) {
        return false;
    }
    if (head.Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }
    pe.machine = head.FileHeader.Machine;
    pe.numberOfSections = head.FileHeader.NumberOfSections;
    pe.sizeOfOptionalHeader = head.FileHeader.SizeOfOptionalHeader;

    // The magic decides which optional header layout follows, and with it the image's
    // bitness -- the one thing about a module we cannot get from the TTD module list.
    TTD::GuestAddress optAddr = moduleBaseAddress + pe.ntOffset + kOptionalHeaderOffset;
    uint16_t magic = 0;
    if (!readMemory(cursor, optAddr, &magic, sizeof(magic))) {
        return false;
    }

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt{};
        if (!readMemory(cursor, optAddr, &opt, sizeof(opt))) {
            return false;
        }
        pe.is64 = true;
        std::memcpy(pe.dataDir, opt.DataDirectory, sizeof(pe.dataDir));
        return true;
    }
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt{};
        if (!readMemory(cursor, optAddr, &opt, sizeof(opt))) {
            return false;
        }
        pe.is64 = false;
        std::memcpy(pe.dataDir, opt.DataDirectory, sizeof(pe.dataDir));
        return true;
    }
    return false;
}

bool isPrintableASCII(unsigned char c) {
    return c == '\t' || (c >= 0x20 && c <= 0x7e);
}

}  // namespace

std::string getModuleBaseName(const std::wstring& full) {
    size_t slash = full.find_last_of(L"\\/");
    std::wstring name = (slash == std::wstring::npos) ? full : full.substr(slash + 1);
    size_t dot = name.find_last_of(L'.');
    if (dot != std::wstring::npos) {
        name = name.substr(0, dot);
    }
    // narrow ASCII-only module name
    std::string out;
    out.reserve(name.size());
    for (wchar_t wc : name) {
        out.push_back(static_cast<char>(wc & 0x7f));
    }
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool getModuleFormat(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, ModuleFormat& out) {
    PeHeaders pe{};
    if (!readNTHeaders(cursor, moduleBaseAddress, pe)) {
        return false;
    }
    out.is64 = pe.is64;
    out.machine = pe.machine;
    return true;
}

const char* archName(const ModuleFormat& format) {
    switch (format.machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_ARM64: return "arm64";
        case IMAGE_FILE_MACHINE_ARMNT:
        case IMAGE_FILE_MACHINE_ARM:   return "arm";
        default: break;
    }
    return format.is64 ? "x64" : "x86";
}

bool getModuleExports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::pair<uint64_t, std::string>>& out, bool* is64Bit) {
    PeHeaders pe{};
    if (!readNTHeaders(cursor, moduleBaseAddress, pe)) {
        return false;
    }
    if (is64Bit != nullptr) {
        *is64Bit = pe.is64;
    }

    const IMAGE_DATA_DIRECTORY& dir = pe.dataDir[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;  // valid PE, just no exports
    }

    IMAGE_EXPORT_DIRECTORY exp{};
    if (!readMemory(cursor, moduleBaseAddress + dir.VirtualAddress, &exp, sizeof(exp))) {
        return false;
    }

    const uint32_t dir_begin = dir.VirtualAddress;
    const uint32_t dir_end = dir.VirtualAddress + dir.Size;

    // Walk the name table; each name maps (via the ordinal table) to a function RVA.
    for (uint32_t i = 0; i < exp.NumberOfNames; ++i) {
        uint32_t name_rva = 0;
        if (!readMemory(cursor, moduleBaseAddress + exp.AddressOfNames + i * sizeof(uint32_t), &name_rva, sizeof(name_rva))) {
            break;
        }

        uint16_t ordinal = 0;
        if (!readMemory(cursor, moduleBaseAddress + exp.AddressOfNameOrdinals + i * sizeof(uint16_t), &ordinal, sizeof(ordinal))) {
            break;
        }

        if (ordinal >= exp.NumberOfFunctions) {
            continue;
        }

        uint32_t func_rva = 0;
        if (!readMemory(cursor, moduleBaseAddress + exp.AddressOfFunctions + ordinal * sizeof(uint32_t), &func_rva, sizeof(func_rva))) {
            continue;
        }

        if (func_rva == 0) {
            continue;
        }

        // Skip forwarded exports
        if (func_rva >= dir_begin && func_rva < dir_end) {
            continue;
        }

        std::string name = readCSTR(cursor, moduleBaseAddress + name_rva);

        // Skip empty export names (possibly due to error in parsing name)
        if (name.empty()) {
            continue;
        }

        out.emplace_back((uint64_t)(moduleBaseAddress + func_rva), std::move(name));
    }
    return true;
}

bool getFunctionEnd(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, uint64_t entry, uint64_t& end) {
    PeHeaders pe{};
    if (!readNTHeaders(cursor, moduleBaseAddress, pe) || !pe.is64) {
        return false;  // only PE32+ images carry a function table
    }
    const IMAGE_DATA_DIRECTORY& dir = pe.dataDir[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    const uint64_t base = static_cast<uint64_t>(moduleBaseAddress);
    if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY) || entry < base) {
        return false;
    }
    const uint64_t rva = entry - base;

    // The table is sorted by BeginAddress, so a binary search reads a dozen entries rather
    // than the whole directory.
    size_t lo = 0, hi = dir.Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        IMAGE_RUNTIME_FUNCTION_ENTRY rf{};
        if (readMemory(cursor, moduleBaseAddress + dir.VirtualAddress + mid * sizeof(rf), &rf, sizeof(rf)) != sizeof(rf)) {
            return false;
        }
        if (rf.BeginAddress == rva) {
            end = base + rf.EndAddress;
            return true;
        }
        if (rf.BeginAddress < rva) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return false;
}

bool getModuleImports(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<ImportRecord>& out) {
    PeHeaders pe{};

    if (!readNTHeaders(cursor, moduleBaseAddress, pe)) {
        return false;
    }

    const IMAGE_DATA_DIRECTORY& dir = pe.dataDir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        return true;
    }

    for (uint32_t idx = 0;; ++idx) {
        IMAGE_IMPORT_DESCRIPTOR desc{};

        if (!readMemory(cursor, moduleBaseAddress + dir.VirtualAddress + idx * sizeof(IMAGE_IMPORT_DESCRIPTOR), &desc, sizeof(desc))) {
            break;
        }

        if (desc.Name == 0 && desc.FirstThunk == 0) {
            break;  // null terminator
        }

        std::string dll = readCSTR(cursor, moduleBaseAddress + desc.Name, 128);

        // OriginalFirstThunk (the import name table) survives binding; fall back to
        // FirstThunk if it is absent.
        uint32_t int_rva = desc.OriginalFirstThunk ? desc.OriginalFirstThunk : desc.FirstThunk;
        uint32_t iat_rva = desc.FirstThunk;
        if (int_rva == 0) {
            continue;
        }

        // Thunks are pointer-sized, so a PE32 image's import tables are half as wide.
        const uint32_t thunkSize = pe.pointerSize();
        const uint64_t ordinalFlag = pe.is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;

        for (uint32_t t = 0;; ++t) {
            uint64_t thunk = 0;
            if (!readMemory(cursor, moduleBaseAddress + int_rva + t * thunkSize, &thunk, thunkSize) || thunk == 0) {
                break;
            }

            TTD::GuestAddress slot_va = moduleBaseAddress + iat_rva + t * thunkSize;

            if (thunk & ordinalFlag) {
                // import by ordinal: no name to match against; record a synthetic name
                ImportRecord rec;
                rec.dll = dll;
                rec.name = "#" + std::to_string(static_cast<uint16_t>(thunk & 0xffff));
                rec.va = slot_va;
                out.push_back(std::move(rec));
            } else {
                // import by name: thunk -> IMAGE_IMPORT_BY_NAME { WORD Hint; CHAR Name[]; }
                std::string name = readCSTR(cursor, moduleBaseAddress + (thunk & 0x7fffffff) + sizeof(uint16_t));
                if (!name.empty()) {
                    ImportRecord rec;
                    rec.dll = dll;
                    rec.name = std::move(name);
                    rec.va = slot_va;
                    out.push_back(std::move(rec));
                }
            }
        }
    }
    return true;
}

bool getModuleSections(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<SectionRecord>& out) {
    PeHeaders pe{};

    if (!readNTHeaders(cursor, moduleBaseAddress, pe)) {
        return false;
    }

    // section headers follow the optional header
    TTD::GuestAddress sect_va = moduleBaseAddress + pe.sectionTableOffset();

    for (uint16_t i = 0; i < pe.numberOfSections; ++i) {
        IMAGE_SECTION_HEADER sh{};

        if (!readMemory(cursor, sect_va + i * sizeof(IMAGE_SECTION_HEADER), &sh, sizeof(sh))) {
            break;
        }

        char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        std::memcpy(name, sh.Name, IMAGE_SIZEOF_SHORT_NAME);
        SectionRecord rec;
        rec.name = name;
        rec.va = moduleBaseAddress + sh.VirtualAddress;
        out.push_back(std::move(rec));
    }
    return true;
}

bool getModuleStrings(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBaseAddress, std::vector<std::string>& out, size_t minLength, size_t maxStrings) {
    PeHeaders pe{};

    if (!readNTHeaders(cursor, moduleBaseAddress, pe)) {
        return false;
    }

    TTD::GuestAddress sect_va = moduleBaseAddress + pe.sectionTableOffset();

    for (uint16_t i = 0; i < pe.numberOfSections && out.size() < maxStrings; ++i) {
        IMAGE_SECTION_HEADER sh{};
        if (!readMemory(cursor, sect_va + i * sizeof(IMAGE_SECTION_HEADER), &sh, sizeof(sh))) {
            break;
        }

        // executable code sections are mostly noise for string recovery; skip them
        if (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            continue;
        }

        uint32_t vsize = sh.Misc.VirtualSize ? sh.Misc.VirtualSize : sh.SizeOfRawData;
        if (vsize == 0 || vsize > 64 * 1024 * 1024) {
            continue;
        }

        std::vector<uint8_t> buf(vsize);
        size_t got = readMemory(cursor, moduleBaseAddress + sh.VirtualAddress, buf.data(), buf.size());
        if (got == 0) {
            continue;
        }

        buf.resize(got);

        // ASCII runs
        std::string cur;
        for (size_t p = 0; p < buf.size() && out.size() < maxStrings; ++p) {
            if (isPrintableASCII(buf[p])) {
                cur.push_back(static_cast<char>(buf[p]));
            } else {
                if (cur.size() >= minLength) {
                    out.push_back(cur);
                }
                cur.clear();
            }
        }

        if (cur.size() >= minLength && out.size() < maxStrings) {
            out.push_back(cur);
        }

        // UTF-16LE runs (printable ASCII char followed by 0x00)
        cur.clear();
        for (size_t p = 0; p + 1 < buf.size() && out.size() < maxStrings; p += 2) {
            if (buf[p + 1] == 0 && isPrintableASCII(buf[p])) {
                cur.push_back(static_cast<char>(buf[p]));
            } else {
                if (cur.size() >= minLength) {
                    out.push_back(cur);
                }
                cur.clear();
            }
        }

        if (cur.size() >= minLength && out.size() < maxStrings) {
            out.push_back(cur);
        }
    }
    return true;
}

}  // namespace ttdcapa
