#ifndef CODESCAN_REGIONPROVIDER_HPP
#define CODESCAN_REGIONPROVIDER_HPP

#include "CallCapturer.hpp"
#include "TraceSession.hpp"
#include "Region.hpp"

#include <optional>
#include <utility>
#include <vector>

#include <TTD/IReplayEngine.h>

namespace discovery {
    struct DiscoveryContext {
        ttd::TraceSession& session;    // NewCursor() for deferred re-query; engine for module list
        MemoryRegions& regions;
        // Holds whatever the capture replay already recovered for the deferred out-params
        ttd::OutParamResolver& outParams;
    };

    // One watched syscall, described entirely by data: which export to hook, its argument count,
    // and which arguments carry the out-params. Anything beyond that goes in one of the two hooks.
    class RegionProvider {
    public:
        // Which arguments hold PVOID* BaseAddress, PSIZE_T RegionSize, and the protection value
        struct OutParamLayout {
            size_t baseArgIdx = 0;
            size_t sizeArgIdx = 0;
            size_t protectArgIdx = 0;
        };

        RegionProvider(const wchar_t* module, const char* function, size_t argCount, OutParamLayout layout, const char* trackedNoun = "region");
        virtual ~RegionProvider() = default;

        virtual void registerBreakpoints(TTD::Replay::UniqueReplayEngine*, ttd::CallCapturer&);

        // Fired at each matched return during CallCapturer::Run(). Reads the out-params named by
        // the layout, deferring any the kernel wrote that ThreadLocal cannot see yet.
        virtual void callback(const ttd::FunctionCall&, TTD::Replay::IThreadView const*);

        // The resolver deferrals are registered with, shared with the capturer driving the replay.
        void setOutParamResolver(ttd::OutParamResolver* resolver) { this->m_outParams = resolver; }

        // Post-run: resolve deferrals and merge into ctx.regions. Runs in registration order.
        virtual void finalize(DiscoveryContext&);

        std::vector<Region> discoveredRegions;
    protected:
        // Hook: reject a captured call before its out-params are read. NTSTATUS and arity are
        // already checked by then.
        virtual bool acceptCall(const ttd::FunctionCall&) { return true; }
        // Hook: reject a resolved region before it is merged into the shared set
        virtual bool acceptRegion(DiscoveryContext&, Region const&) { return true; }

        // Hook: whether a call whose out-params never resolved may still be approximated from
        // the caller's request. Worth it where the region would otherwise go unscanned; not
        // where a wrong range does active harm rather than merely wasting a scan.
        virtual bool approximateUnresolved() const { return true; }

        // Reads *pBase / *pSize via ThreadLocal. Returns a Region when both are non-zero, or
        // defers and returns nullopt when either still reads back the caller's stale 0.
        std::optional<Region> tryReadOutParams(const ttd::FunctionCall&, TTD::Replay::IThreadView const*, uint32_t protect);

        // Re-queries every deferred out-param and appends whatever it recovers to discoveredRegions
        void resolveDeferred(DiscoveryContext&);
        // Merges the accepted regions into the shared set. Returns how many were added.
        size_t mergeInto(DiscoveryContext&);

        struct Deferred {
            TTD::Replay::Position retPos;
            TTD::Replay::UniqueThreadId utid;  // the thread that made the call, for the read-back replay
            uint64_t pBase;
            uint64_t pSize;
            uint32_t protect;
            // Guest pointer width in bytes; every re-read of the two slots below has to
            // use the same one the capture did or it recovers a different number.
            uint32_t width = sizeof(uint64_t);
            // What the in-replay resolver was asked for, and what ThreadLocal could already see.
            // The stale values are the caller's own request: not the kernel's answer, but a floor
            // for it, and the last resort if nothing better turns up.
            ttd::OutParamResolver::Token baseToken = ttd::OutParamResolver::NoToken;
            ttd::OutParamResolver::Token sizeToken = ttd::OutParamResolver::NoToken;
            uint64_t staleBase = 0;
            uint64_t staleSize = 0;
        };
        std::vector<Deferred> m_deferred;

        ttd::OutParamResolver* m_outParams = nullptr;

        const wchar_t* m_moduleName;
        const char* m_functionName;
        size_t m_argCount = 0;
        OutParamLayout m_layout;
        const char* m_trackedNoun;  // what finalize() calls the things it merged, for the console
    };

    // NtAllocateVirtualMemory(HANDLE, PVOID* BaseAddress, ULONG_PTR, PSIZE_T RegionSize, ULONG, ULONG Protect)
    class NtAllocateVirtualMemoryProvider : public RegionProvider {
        public:
            NtAllocateVirtualMemoryProvider() : RegionProvider(L"ntdll.dll", "NtAllocateVirtualMemory", 6, { 1, 3, 5 }) {};
    };

    // NtMapViewOfSection(HANDLE, HANDLE, PVOID* BaseAddress, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
    //                    PSIZE_T ViewSize, SECTION_INHERIT, ULONG, ULONG Win32Protect)
    class NtMapViewOfSectionProvider : public RegionProvider {
        public:
            NtMapViewOfSectionProvider() : RegionProvider(L"ntdll.dll", "NtMapViewOfSection", 10, { 2, 6, 9 }, "manually-mapped section view") {};
        protected:
            // Views the loader reported as a module load are ordinary DLL loads, not manual maps
            bool acceptRegion(DiscoveryContext&, Region const&) override;
        private:
            // [base, end) of every module the trace saw loaded, built once on first use
            std::vector<std::pair<uint64_t, uint64_t>> m_moduleRanges;
    };

    // NtProtectVirtualMemory(HANDLE, PVOID* BaseAddress, PSIZE_T NumberOfBytes, ULONG NewProtect, PULONG)
    class NtProtectVirtualMemoryProvider : public RegionProvider {
        public:
            NtProtectVirtualMemoryProvider() : RegionProvider(L"ntdll.dll", "NtProtectVirtualMemory", 5, { 1, 2, 3 }) {};
            // Produces no regions of its own; reclassifies the ones other providers found
            void finalize(DiscoveryContext&) override;
        protected:
            bool acceptCall(const ttd::FunctionCall&) override;
            // What this provider's ranges do is flip *overlapping* regions to executable, so an
            // approximated range does not cost a missed scan the way it would elsewhere -- it
            // relabels somebody else's data region as code and changes what capa disassembles.
            // A protect event that could not be resolved is dropped instead.
            bool approximateUnresolved() const override { return false; }
    };
}

#endif
