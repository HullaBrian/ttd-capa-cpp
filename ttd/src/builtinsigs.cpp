#include "builtinsigs.hpp"

namespace ttdcapa::win32meta {
    namespace {

        constexpr uint8_t kIn = AttrIn;
        constexpr uint8_t kOut = AttrOut;
        constexpr uint8_t kInOut = AttrIn | AttrOut;
        constexpr uint8_t kInOpt = AttrIn | AttrOptional;

        // Every parameter below is pointer-sized or smaller, so the x86 footprint is
        // 4 in all but the one 64-bit case, which is why BuiltinParam defaults it.
        constexpr uint16_t kPtr = 8;

        // -------------------------------------------------------------------
        // 1. win32u -- the win32k syscall stubs phnt's ntuser.h does not declare
        // -------------------------------------------------------------------
        //
        // Only the ones whose prototypes are not in doubt. NtUserCreateWindowEx and
        // NtUserRegisterClassExWOW are deliberately absent: they take a dozen-odd
        // parameters whose order is documented only by reimplementations, they
        // accounted for eight calls in the trace that motivated this, and a wrong
        // arity would misattribute every argument after the mistake.

        // SHORT NtUserGetAsyncKeyState(int Key)
        //
        // 576,705 calls in one desktop trace -- the inner syscall of the
        // GetAsyncKeyState polling loop, and on its own the largest single source of
        // invented arguments in the whole report.
        constexpr BuiltinParam kNtUserGetAsyncKeyState[] = {
            { "Key", "int", ArgKind::Integer, kIn, 4 },
        };

        // ULONG NtUserGetAtomName(ATOM Atom, PUNICODE_STRING AtomName)
        constexpr BuiltinParam kNtUserGetAtomName[] = {
            { "Atom",     "ATOM",             ArgKind::Integer,           kIn,  2 },
            { "AtomName", "UNICODE_STRING*",  ArgKind::CountedWideString, kOut, 16 },
        };

        // UINT NtUserRegisterWindowMessage(PUNICODE_STRING MessageName)
        constexpr BuiltinParam kNtUserRegisterWindowMessage[] = {
            { "MessageName", "UNICODE_STRING*", ArgKind::CountedWideString, kIn, 16 },
        };

        // BOOL NtUserUnregisterClass(PUNICODE_STRING ClassName, HINSTANCE Instance,
        //                            PVOID ClassMenuName)
        constexpr BuiltinParam kNtUserUnregisterClass[] = {
            { "ClassName",     "UNICODE_STRING*", ArgKind::CountedWideString, kIn,  16 },
            { "Instance",      "HINSTANCE",       ArgKind::Handle,            kIn,  kPtr },
            { "ClassMenuName", "PVOID",           ArgKind::Pointer,           kOut, 0 },
        };

        // -------------------------------------------------------------------
        // 2. the C runtime, exported by ntdll, msvcrt and ucrtbase
        // -------------------------------------------------------------------
        //
        // Standard C. ucrtbase additionally exports `_o_`-prefixed forwarders with
        // identical signatures, listed at the bottom against the same tables.
        //
        // These are worth signing not because a rule matches on strlen, but because
        // an unsignatured call reports four argument registers and any of them that
        // happens to point at text is rendered as a string. memset alone was 60,650
        // calls; that is 60,650 chances to invent a string feature.

        // Dest is left an opaque pointer on purpose. Capturing it would add a few
        // hundred bytes of hex to every one of 60,000 calls to say what Value and
        // Count already say, and the same content is captured once from Src on the
        // copies, where it is actual evidence.
        constexpr BuiltinParam kMemset[] = {
            { "Dest",  "void*",  ArgKind::Pointer, kIn, 0 },
            { "Value", "int",    ArgKind::Integer, kIn, 4 },
            { "Count", "size_t", ArgKind::Integer, kIn, 8 },
        };

        constexpr BuiltinParam kMemcpy[] = {
            { "Dest",  "void*",       ArgKind::Pointer,    kIn, 0 },
            { "Src",   "const void*", ArgKind::ByteBuffer, kIn, 1, 4, AuxKind::BytesFromParam, 2 },
            { "Count", "size_t",      ArgKind::Integer,    kIn, 8 },
        };

        constexpr BuiltinParam kMemcmp[] = {
            { "Buf1",  "const void*", ArgKind::ByteBuffer, kIn, 1, 4, AuxKind::BytesFromParam, 2 },
            { "Buf2",  "const void*", ArgKind::ByteBuffer, kIn, 1, 4, AuxKind::BytesFromParam, 2 },
            { "Count", "size_t",      ArgKind::Integer,    kIn, 8 },
        };

        constexpr BuiltinParam kStrOne[] = {
            { "Str", "const char*", ArgKind::AnsiString, kIn, 1 },
        };
        constexpr BuiltinParam kWcsOne[] = {
            { "Str", "const wchar_t*", ArgKind::WideString, kIn, 2 },
        };
        constexpr BuiltinParam kStrTwo[] = {
            { "Str1", "const char*", ArgKind::AnsiString, kIn, 1 },
            { "Str2", "const char*", ArgKind::AnsiString, kIn, 1 },
        };
        constexpr BuiltinParam kWcsTwo[] = {
            { "Str1", "const wchar_t*", ArgKind::WideString, kIn, 2 },
            { "Str2", "const wchar_t*", ArgKind::WideString, kIn, 2 },
        };
        constexpr BuiltinParam kStrTwoCount[] = {
            { "Str1",  "const char*", ArgKind::AnsiString, kIn, 1 },
            { "Str2",  "const char*", ArgKind::AnsiString, kIn, 1 },
            { "Count", "size_t",      ArgKind::Integer,    kIn, 8 },
        };
        constexpr BuiltinParam kWcsTwoCount[] = {
            { "Str1",  "const wchar_t*", ArgKind::WideString, kIn, 2 },
            { "Str2",  "const wchar_t*", ArgKind::WideString, kIn, 2 },
            { "Count", "size_t",         ArgKind::Integer,    kIn, 8 },
        };
        constexpr BuiltinParam kStrChr[] = {
            { "Str", "const char*", ArgKind::AnsiString, kIn, 1 },
            { "C",   "int",         ArgKind::Integer,    kIn, 4 },
        };
        constexpr BuiltinParam kWcsChr[] = {
            { "Str", "const wchar_t*", ArgKind::WideString, kIn, 2 },
            { "C",   "wchar_t",        ArgKind::Integer,    kIn, 2 },
        };
        constexpr BuiltinParam kStrCopy[] = {
            { "Dest", "char*",       ArgKind::AnsiString, kOut, 1 },
            { "Src",  "const char*", ArgKind::AnsiString, kIn,  1 },
        };
        constexpr BuiltinParam kWcsCopyS[] = {
            { "Dest",  "wchar_t*",       ArgKind::WideString, kOut, 2 },
            { "Count", "size_t",         ArgKind::Integer,    kIn,  8 },
            { "Src",   "const wchar_t*", ArgKind::WideString, kIn,  2 },
        };
        constexpr BuiltinParam kStrCopyS[] = {
            { "Dest",  "char*",       ArgKind::AnsiString, kOut, 1 },
            { "Count", "size_t",      ArgKind::Integer,    kIn,  8 },
            { "Src",   "const char*", ArgKind::AnsiString, kIn,  1 },
        };

        constexpr BuiltinParam kMalloc[] = {
            { "Size", "size_t", ArgKind::Integer, kIn, 8 },
        };
        constexpr BuiltinParam kFree[] = {
            { "Block", "void*", ArgKind::Pointer, kIn, 0 },
        };
        constexpr BuiltinParam kRealloc[] = {
            { "Block", "void*",  ArgKind::Pointer, kInOpt, 0 },
            { "Size",  "size_t", ArgKind::Integer, kIn,    8 },
        };
        constexpr BuiltinParam kCalloc[] = {
            { "Count", "size_t", ArgKind::Integer, kIn, 8 },
            { "Size",  "size_t", ArgKind::Integer, kIn, 8 },
        };

        constexpr BuiltinParam kIntOne[] = {
            { "C", "int", ArgKind::Integer, kIn, 4 },
        };
        constexpr BuiltinParam kIsLeadByteL[] = {
            { "C",      "int",       ArgKind::Integer, kIn,    4 },
            { "Locale", "_locale_t", ArgKind::Pointer, kInOpt, 0 },
        };
        constexpr BuiltinParam kIswctype[] = {
            { "C",    "wint_t",   ArgKind::Integer, kIn, 4 },
            { "Type", "wctype_t", ArgKind::Integer, kIn, 2 },
        };
        constexpr BuiltinParam kAtoi[] = {
            { "Str", "const char*", ArgKind::AnsiString, kIn, 1 },
        };

        // int _vsnprintf(char *Buffer, size_t Count, const char *Format, va_list Args)
        //
        // The format string is the point: it is the one argument of a printf-family
        // call that says what the call is doing.
        constexpr BuiltinParam kVsnprintf[] = {
            { "Buffer", "char*",       ArgKind::AnsiString, kOut,   1 },
            { "Count",  "size_t",      ArgKind::Integer,    kIn,    8 },
            { "Format", "const char*", ArgKind::AnsiString, kIn,    1 },
            { "Args",   "va_list",     ArgKind::Pointer,    kInOpt, 0 },
        };
        constexpr BuiltinParam kVsnwprintf[] = {
            { "Buffer", "wchar_t*",       ArgKind::WideString, kOut,   2 },
            { "Count",  "size_t",         ArgKind::Integer,    kIn,    8 },
            { "Format", "const wchar_t*", ArgKind::WideString, kIn,    2 },
            { "Args",   "va_list",        ArgKind::Pointer,    kInOpt, 0 },
        };
        // sprintf is variadic. Only the two fixed parameters are declared, which is
        // both correct and the useful part; the variadic tail has no fixed layout.
        constexpr BuiltinParam kSprintf[] = {
            { "Buffer", "char*",       ArgKind::AnsiString, kOut, 1 },
            { "Format", "const char*", ArgKind::AnsiString, kIn,  1 },
        };

        constexpr BuiltinParam kBsearch[] = {
            { "Key",     "const void*", ArgKind::Pointer, kIn, 0 },
            { "Base",    "const void*", ArgKind::Pointer, kIn, 0 },
            { "Num",     "size_t",      ArgKind::Integer, kIn, 8 },
            { "Width",   "size_t",      ArgKind::Integer, kIn, 8 },
            { "Compare", "int (*)()",   ArgKind::FuncPtr, kIn, kPtr },
        };
        constexpr BuiltinParam kQsort[] = {
            { "Base",    "void*",     ArgKind::Pointer, kInOut, 0 },
            { "Num",     "size_t",    ArgKind::Integer, kIn,    8 },
            { "Width",   "size_t",    ArgKind::Integer, kIn,    8 },
            { "Compare", "int (*)()", ArgKind::FuncPtr, kIn,    kPtr },
        };

        // void RtlCopyMemory(void *Destination, const void *Source, SIZE_T Length)
        //
        // ntdll exports it as a real function even though the SDK defines it as a
        // macro, which is why no header declares it and phnt cannot supply it.
        constexpr BuiltinParam kRtlCopyMemory[] = {
            { "Destination", "void*",       ArgKind::Pointer,    kIn, 0 },
            { "Source",      "const void*", ArgKind::ByteBuffer, kIn, 1, 4, AuxKind::BytesFromParam, 2 },
            { "Length",      "SIZE_T",      ArgKind::Integer,    kIn, 8 },
        };

        // operator delete / operator delete[] -- one pointer each. Mangled names are
        // what the export table carries, so that is what the index has to be keyed on.
        constexpr BuiltinParam kOperatorDelete[] = {
            { "Block", "void*", ArgKind::Pointer, kIn, 0 },
        };

        template <size_t N>
        constexpr BuiltinFunc fn(const char* name, const char* dll, const BuiltinParam (&params)[N]) {
            return BuiltinFunc{ name, dll, params, static_cast<uint8_t>(N) };
        }

        constexpr BuiltinFunc kTable[] = {
            // --- win32u ---
            fn("NtUserGetAsyncKeyState", "win32u.dll", kNtUserGetAsyncKeyState),
            fn("NtUserGetAtomName", "win32u.dll", kNtUserGetAtomName),
            fn("NtUserRegisterWindowMessage", "win32u.dll", kNtUserRegisterWindowMessage),
            fn("NtUserUnregisterClass", "win32u.dll", kNtUserUnregisterClass),
            // HWND ABI_Get_ForegroundWindow(VOID) -- the win32u shim for
            // GetForegroundWindow, which takes no arguments.
            BuiltinFunc{ "ABI_Get_ForegroundWindow", "win32u.dll", nullptr, 0 },

            // --- memory ---
            fn("memset", "ntdll.dll", kMemset),
            fn("memcpy", "ntdll.dll", kMemcpy),
            fn("memmove", "ntdll.dll", kMemcpy),
            fn("memcmp", "ntdll.dll", kMemcmp),
            fn("RtlCopyMemory", "ntdll.dll", kRtlCopyMemory),
            fn("RtlMoveMemory", "ntdll.dll", kRtlCopyMemory),

            // --- narrow strings ---
            fn("strlen", "ntdll.dll", kStrOne),
            fn("strcmp", "ntdll.dll", kStrTwo),
            fn("strncmp", "ntdll.dll", kStrTwoCount),
            fn("_stricmp", "ntdll.dll", kStrTwo),
            fn("_strcmpi", "ntdll.dll", kStrTwo),
            fn("_strnicmp", "ntdll.dll", kStrTwoCount),
            fn("strchr", "ntdll.dll", kStrChr),
            fn("strrchr", "ntdll.dll", kStrChr),
            fn("strstr", "ntdll.dll", kStrTwo),
            fn("strcpy", "ntdll.dll", kStrCopy),
            fn("strcat", "ntdll.dll", kStrCopy),
            fn("strcpy_s", "ntdll.dll", kStrCopyS),
            fn("strcat_s", "ntdll.dll", kStrCopyS),

            // --- wide strings ---
            fn("wcslen", "ntdll.dll", kWcsOne),
            fn("wcscmp", "ntdll.dll", kWcsTwo),
            fn("wcsncmp", "ntdll.dll", kWcsTwoCount),
            fn("_wcsicmp", "ntdll.dll", kWcsTwo),
            fn("_wcsnicmp", "ntdll.dll", kWcsTwoCount),
            fn("wcschr", "ntdll.dll", kWcsChr),
            fn("wcsrchr", "ntdll.dll", kWcsChr),
            fn("wcsstr", "ntdll.dll", kWcsTwo),
            fn("wcspbrk", "ntdll.dll", kWcsTwo),
            fn("wcscpy_s", "ntdll.dll", kWcsCopyS),
            fn("wcscat_s", "ntdll.dll", kWcsCopyS),
            fn("vswprintf_s", "ntdll.dll", kVsnwprintf),

            // --- formatting ---
            fn("_vsnprintf", "ntdll.dll", kVsnprintf),
            fn("_vsnprintf_l", "ntdll.dll", kVsnprintf),
            fn("_vsnwprintf", "ntdll.dll", kVsnwprintf),
            fn("_vsnwprintf_l", "ntdll.dll", kVsnwprintf),
            fn("sprintf", "ntdll.dll", kSprintf),
            fn("swprintf", "ntdll.dll", kSprintf),

            // --- allocation ---
            fn("malloc", "ntdll.dll", kMalloc),
            fn("free", "ntdll.dll", kFree),
            fn("realloc", "ntdll.dll", kRealloc),
            fn("calloc", "ntdll.dll", kCalloc),
            fn("_msize", "ntdll.dll", kFree),
            fn("_free_base", "ucrtbase.dll", kFree),
            fn("_realloc_base", "ucrtbase.dll", kRealloc),
            fn("_calloc_base", "ucrtbase.dll", kCalloc),
            fn("_malloc_base", "ucrtbase.dll", kMalloc),
            fn("??3@YAXPEAX@Z", "msvcrt.dll", kOperatorDelete),
            fn("??_V@YAXPEAX@Z", "msvcrt.dll", kOperatorDelete),

            // --- character classification and conversion ---
            fn("_isleadbyte_l", "msvcrt.dll", kIsLeadByteL),
            fn("iswctype", "ntdll.dll", kIswctype),
            fn("isdigit", "ntdll.dll", kIntOne),
            fn("isalpha", "ntdll.dll", kIntOne),
            fn("isspace", "ntdll.dll", kIntOne),
            fn("__isascii", "ntdll.dll", kIntOne),
            fn("tolower", "ntdll.dll", kIntOne),
            fn("toupper", "ntdll.dll", kIntOne),
            fn("towlower", "ntdll.dll", kIntOne),
            fn("towupper", "ntdll.dll", kIntOne),
            fn("atoi", "ntdll.dll", kAtoi),
            fn("atol", "ntdll.dll", kAtoi),

            // --- searching and sorting ---
            fn("bsearch", "ntdll.dll", kBsearch),
            fn("qsort", "ntdll.dll", kQsort),

            // ucrtbase publishes `_o_`-prefixed forwarders with identical signatures.
            fn("_o__wcsicmp", "ucrtbase.dll", kWcsTwo),
            fn("_o__wcsnicmp", "ucrtbase.dll", kWcsTwoCount),
            fn("_o__stricmp", "ucrtbase.dll", kStrTwo),
            fn("_o_memset", "ucrtbase.dll", kMemset),
            fn("_o_memcpy", "ucrtbase.dll", kMemcpy),
            fn("_o_tolower", "ucrtbase.dll", kIntOne),
            fn("_o_toupper", "ucrtbase.dll", kIntOne),
            fn("_o_towupper", "ucrtbase.dll", kIntOne),
            fn("_o_towlower", "ucrtbase.dll", kIntOne),
            fn("_o_wcscpy_s", "ucrtbase.dll", kWcsCopyS),
            fn("_o_wcscat_s", "ucrtbase.dll", kWcsCopyS),
            fn("_o_malloc", "ucrtbase.dll", kMalloc),
            fn("_o_free", "ucrtbase.dll", kFree),
        };

        // -------------------------------------------------------------------
        // 3. the flag-enum overlay
        // -------------------------------------------------------------------
        //
        // phnt types every flag argument as a bare ULONG, so this names the
        // win32json enum table that describes one. Only the arguments an analyst
        // actually reads: memory protection, allocation type, and the file-creation
        // flags. An entry whose enum win32json never referenced is skipped at load,
        // and the parameter renders as a number.
        constexpr EnumOverlay kEnumOverlays[] = {
            { "NtProtectVirtualMemory",  "NewProtection",           "PAGE_PROTECTION_FLAGS" },
            { "NtProtectVirtualMemory",  "OldProtection",           "PAGE_PROTECTION_FLAGS" },
            { "NtAllocateVirtualMemory", "PageProtection",          "PAGE_PROTECTION_FLAGS" },
            { "NtAllocateVirtualMemory", "AllocationType",          "VIRTUAL_ALLOCATION_TYPE" },
            { "NtAllocateVirtualMemoryEx", "PageProtection",        "PAGE_PROTECTION_FLAGS" },
            { "NtAllocateVirtualMemoryEx", "AllocationType",        "VIRTUAL_ALLOCATION_TYPE" },
            { "NtFreeVirtualMemory",     "FreeType",                "VIRTUAL_FREE_TYPE" },
            { "NtCreateSection",         "SectionPageProtection",   "PAGE_PROTECTION_FLAGS" },
            { "NtCreateSectionEx",       "SectionPageProtection",   "PAGE_PROTECTION_FLAGS" },
            { "NtMapViewOfSection",      "PageProtection",          "PAGE_PROTECTION_FLAGS" },
            { "NtMapViewOfSectionEx",    "PageProtection",          "PAGE_PROTECTION_FLAGS" },
            { "NtCreateFile",            "CreateDisposition",       "NT_CREATE_FILE_DISPOSITION" },
            { "NtCreateFile",            "ShareAccess",             "FILE_SHARE_MODE" },
            { "NtCreateFile",            "FileAttributes",          "FILE_FLAGS_AND_ATTRIBUTES" },
            { "NtOpenFile",              "ShareAccess",             "FILE_SHARE_MODE" },
            { "NtQueryInformationProcess", "ProcessInformationClass", "PROCESSINFOCLASS" },
        };

    }  // namespace

    std::span<const BuiltinFunc> builtinSignatures() {
        return std::span<const BuiltinFunc>(kTable, std::size(kTable));
    }

    std::span<const EnumOverlay> builtinEnumOverlays() {
        return std::span<const EnumOverlay>(kEnumOverlays, std::size(kEnumOverlays));
    }

}  // namespace ttdcapa::win32meta
