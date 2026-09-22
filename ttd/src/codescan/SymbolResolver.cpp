#include "Utils.hpp"
#include "SymbolResolver.hpp"

#include <windows.h>
#include <vector>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

TTD::GuestAddress ttd::ResolveExport(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress moduleBase,
                                     const char* exportName, bool* is64Bit) {
    IMAGE_DOS_HEADER dos;
    if (!ttd::ReadMemory(cursor, moduleBase, sizeof(dos), &dos)) return (TTD::GuestAddress)0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return (TTD::GuestAddress)0;

    // Only the optional header differs between the two PE formats, and the signature and
    // IMAGE_FILE_HEADER ahead of it are identical -- so read up to the magic, then read the
    // optional header the magic says is there. Reading a PE32 image as PE32+ would put the
    // data directory 16 bytes past where it really is, and the export lookup would fail (or,
    // worse, land on whatever follows) for every 32-bit module in the trace.
    uint32_t const optOffset = static_cast<uint32_t>(dos.e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
    uint32_t signature = 0;
    if (!ttd::ReadMemory(cursor, moduleBase + dos.e_lfanew, sizeof(signature), &signature)) return (TTD::GuestAddress)0;
    if (signature != IMAGE_NT_SIGNATURE) return (TTD::GuestAddress)0;

    uint16_t magic = 0;
    if (!ttd::ReadMemory(cursor, moduleBase + optOffset, sizeof(magic), &magic)) return (TTD::GuestAddress)0;

    IMAGE_DATA_DIRECTORY expDir{};
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        IMAGE_OPTIONAL_HEADER64 opt;
        if (!ttd::ReadMemory(cursor, moduleBase + optOffset, sizeof(opt), &opt)) return (TTD::GuestAddress)0;
        expDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (is64Bit != nullptr) *is64Bit = true;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 opt;
        if (!ttd::ReadMemory(cursor, moduleBase + optOffset, sizeof(opt), &opt)) return (TTD::GuestAddress)0;
        expDir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (is64Bit != nullptr) *is64Bit = false;
    } else {
        return (TTD::GuestAddress)0;
    }

    if (expDir.Size == 0) return (TTD::GuestAddress)0;

    IMAGE_EXPORT_DIRECTORY exp;
    if (!ttd::ReadMemory(cursor, moduleBase + expDir.VirtualAddress, sizeof(exp), &exp)) return (TTD::GuestAddress)0;

    std::vector<DWORD> funcRVAs(exp.NumberOfFunctions);
    std::vector<DWORD> nameRVAs(exp.NumberOfNames);
    std::vector<WORD>  ordinals(exp.NumberOfNames);

    if (!ttd::ReadMemory(cursor, moduleBase + exp.AddressOfFunctions, funcRVAs.size() * sizeof(DWORD), funcRVAs.data())) return (TTD::GuestAddress)0;
    if (!ttd::ReadMemory(cursor, moduleBase + exp.AddressOfNames, nameRVAs.size() * sizeof(DWORD), nameRVAs.data())) return (TTD::GuestAddress)0;
    if (!ttd::ReadMemory(cursor, moduleBase + exp.AddressOfNameOrdinals, ordinals.size() * sizeof(WORD), ordinals.data())) return (TTD::GuestAddress)0;

    for (DWORD i = 0; i < exp.NumberOfNames; ++i) {
        char nameBuf[128] = {};
        if (!ttd::ReadMemory(cursor, moduleBase + nameRVAs[i], sizeof(nameBuf) - 1, nameBuf)) continue;
        if (strcmp(nameBuf, exportName) != 0) continue;

        WORD ord = ordinals[i];
        if (ord >= exp.NumberOfFunctions) return (TTD::GuestAddress)0;
        DWORD funcRVA = funcRVAs[ord];

        if (funcRVA >= expDir.VirtualAddress && funcRVA < expDir.VirtualAddress + expDir.Size) {
            return (TTD::GuestAddress)0;  // forwarder
        }

        return moduleBase + funcRVA;
    }
    return (TTD::GuestAddress)0;
}
