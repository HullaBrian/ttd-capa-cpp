#include "CallCapturer.hpp"
#include "TraceSession.hpp"
#include "Utils.hpp"
#include "Region.hpp"
#include "RegionProviders.hpp"

#include "../log.hpp"

#include <iostream>
#include <format>
#include <optional>
#include <windows.h>
#include <vector>

#include <TTD/IReplayEngine.h>

using discovery::Region;

discovery::RegionProvider::RegionProvider(const wchar_t* module, const char* function, size_t argCount, OutParamLayout layout, const char* trackedNoun)
    : m_moduleName(module)
    , m_functionName(function)
    , m_argCount(argCount)
    , m_layout(layout)
    , m_trackedNoun(trackedNoun)
{}

void discovery::RegionProvider::registerBreakpoints(TTD::Replay::UniqueReplayEngine* engine, ttd::CallCapturer& callCapturer) {
    ttd::CallCapturer::Callback callback = [this](const ttd::FunctionCall& functionCall, TTD::Replay::IThreadView const* threadView) {
        this->callback(functionCall, threadView);
    };

    callCapturer.AddBySymbol(engine, this->m_moduleName, this->m_functionName, callback, this->m_argCount);
}

void discovery::RegionProvider::callback(ttd::FunctionCall const& functionCall, TTD::Replay::IThreadView const* thread) {
    // Filter out failed calls
    if (static_cast<int32_t>(functionCall.ReturnValue) < 0) return;
    if (functionCall.Args.size() < this->m_argCount) return;
    if (!this->acceptCall(functionCall)) return;

    uint32_t const protect = static_cast<uint32_t>(functionCall.Args[this->m_layout.protectArgIdx]);
    std::optional<Region> region = this->tryReadOutParams(functionCall, thread, protect);
    if (region.has_value()) this->discoveredRegions.push_back(*region);
}

std::optional<Region> discovery::RegionProvider::tryReadOutParams(
    ttd::FunctionCall const& functionCall,
    TTD::Replay::IThreadView const* thread,
    uint32_t protect
) {
    uint64_t const pBaseAddress = functionCall.Args[this->m_layout.baseArgIdx];
    uint64_t const pRegionSize = functionCall.Args[this->m_layout.sizeArgIdx];

    // Filter out calls whose out-param pointers are 0s
    if (pBaseAddress == 0 || pRegionSize == 0) return std::nullopt;

    // PVOID* and PSIZE_T are both guest-pointer-sized, so on a 32-bit callee only the
    // low dword belongs to the value. Reading eight bytes there drags in whatever
    // follows on the stack and fails the page-granularity test below -- which would
    // report every 32-bit allocation as unresolvable rather than as wrong.
    uint32_t const width = functionCall.Is64 ? sizeof(uint64_t) : sizeof(uint32_t);

    DWORD64 baseAddress = 0;
    DWORD64 regionSize = 0;

    // Dereference the resulting base address and region size
    bool const readBase = ttd::ReadMemory(thread, TTD::GuestAddress{ pBaseAddress }, width, &baseAddress);
    bool const readSize = ttd::ReadMemory(thread, TTD::GuestAddress{ pRegionSize }, width, &regionSize);

    if (!readBase || !readSize) {
        ttdcapa::log::err() << std::format(
            "[-] [{}] Could not read {} out-params\n",
            ttd::positionToString(functionCall.ReturnPosition),
            this->m_functionName
        );
        return std::nullopt;
    }

    // Accept a half only if it is page-granular. A 0 means the kernel's write to that out-param
    // is not visible in this thread's ThreadLocal record yet, so the pointer still yields the
    // caller's stale value -- but so does a *non-zero* unaligned read, which is the dangerous
    // one: NtAllocateVirtualMemory's wrapper pre-writes the requested size, and taking that at
    // face value reconstructs the region a page short with nothing to indicate it. Which half
    // goes missing varies by syscall, so both are tested the same way.
    if (ttd::isPageGranular(baseAddress) && ttd::isPageGranular(regionSize)) {
        return Region{ baseAddress, regionSize, protect };
    }

    // Register whatever is still the caller's value with the resolver, so the read-back that
    // brings in the kernel's answer is caught by this same replay as it rolls forward.
    Deferred deferred{ functionCall.ReturnPosition, functionCall.Utid, pBaseAddress, pRegionSize, protect };
    deferred.width = width;
    deferred.staleBase = baseAddress;
    deferred.staleSize = regionSize;
    if (this->m_outParams != nullptr) {
        if (!ttd::isPageGranular(baseAddress)) deferred.baseToken = this->m_outParams->submit(functionCall.Utid, pBaseAddress, width);
        if (!ttd::isPageGranular(regionSize)) deferred.sizeToken = this->m_outParams->submit(functionCall.Utid, pRegionSize, width);
    }
    this->m_deferred.push_back(deferred);

    return std::nullopt;
}

// How far past the call to look for the caller reading its out-param back. Kept short because the
// target is usually a stack slot, and a read much later belongs to whatever reused that slot.
static constexpr uint64_t ReadbackStepBudget = 0x2000;

// Recovers one kernel-written out-param, widening the search until something turns up
static bool resolveOutParam(
    ttd::TraceSession& session,
    TTD::Replay::UniqueCursor* cursor,
    TTD::Replay::Position const& retPos,
    TTD::Replay::UniqueThreadId utid,
    uint64_t pointer,
    uint32_t width,
    DWORD64& value
) {
    // InFragmentAggressive searches the whole fragment including future steps, catching the usual
    // case where the caller reads the value back shortly after. GloballyAggressive widens that
    // across fragments at lower confidence. Both zero-fill misses, so a 0 means not found.
    static constexpr TTD::Replay::QueryMemoryPolicy policies[] = {
        TTD::Replay::QueryMemoryPolicy::InFragmentAggressive,
        TTD::Replay::QueryMemoryPolicy::GloballyAggressive,
    };

    for (TTD::Replay::QueryMemoryPolicy policy : policies) {
        value = 0;  // a short read must not leave the previous attempt's high bytes behind
        if (ttd::ReadMemory(cursor, TTD::GuestAddress{ pointer }, width, &value, policy) &&
            ttd::isPageGranular(value)) {
            return true;
        }
    }

    // Both policies search from the call's own position, but a syscall return lands on a sequence
    // boundary, so the read-back often sits in the next fragment where no query here can reach it.
    // Replaying forward finds it wherever it is.
    value = 0;
    return ttd::RecoverByReadback(session, retPos, utid, TTD::GuestAddress{ pointer }, width, &value, ReadbackStepBudget)
        && ttd::isPageGranular(value);
}

// Fills in whichever half was never recovered, from the caller's own request.
//
// The kernel answers a request by snapping it outward: the base to its page floor, the end to
// its page ceiling. The two halves are therefore NOT interchangeable across that rounding --
// a recovered `RegionSize` is measured from the *rounded* base, while the requested size is
// measured from the *requested* base. Deriving one from the other's frame of reference is how
// this lands a page short (missing the tail of a payload, the exact failure the page-granularity
// check exists to prevent) or a page long (overlapping a neighbour, which then loses one of the
// two outright to MemoryRegions::addRegion). So each half is either taken verbatim as recovered,
// or derived from the request in the request's own frame -- never mixed.
static bool approximateFromRequest(uint64_t staleBase, uint64_t staleSize,
                                   bool haveBase, uint64_t recoveredBase,
                                   bool haveSize, uint64_t recoveredSize,
                                   uint64_t& base, uint64_t& size) {
    constexpr uint64_t PageMask = 0xfffull;

    // The base is the recovered one, or the request's page floor.
    if (!haveBase && staleBase == 0) return false;  // nothing at all to go on
    base = haveBase ? recoveredBase : (staleBase & ~PageMask);

    // The end, in whichever frame the requested size was actually measured in.
    uint64_t end = 0;
    if (haveSize) {
        end = base + recoveredSize;                            // recovered: measured from the base
    } else if (staleSize == 0) {
        return false;                                          // no size to go on at all
    } else if (staleBase != 0) {
        end = (staleBase + staleSize + PageMask) & ~PageMask;   // caller named a base: size spans from it
    } else if (haveBase) {
        // The caller passed *BaseAddress == 0, asking the kernel to choose the address; the
        // requested size is then measured from whatever base it chose, which is the one we
        // recovered. Rounding from the request's base is not an option -- there wasn't one.
        end = base + ((staleSize + PageMask) & ~PageMask);
    } else {
        return false;                                          // neither a base nor a frame for the size
    }

    if (end <= base) return false;
    size = end - base;
    return true;
}

void discovery::RegionProvider::resolveDeferred(DiscoveryContext& discoveryContext) {
    if (this->m_deferred.empty()) return;

    // Everything the in-replay resolver already caught costs nothing to collect here; only what
    // it could not answer pays for a cursor, and the cursor is only created if that happens.
    std::optional<TTD::Replay::UniqueCursor> cursor;
    size_t inReplay = 0, postRun = 0, approximated = 0, skipped = 0;

    // Reads one half: the resolver's answer if it caught the read-back, else the value
    // ThreadLocal already had if that was the kernel's (page-granular) answer all along, else
    // the post-run seek-and-widen path.
    auto resolveHalf = [&](Deferred const& deferred, ttd::OutParamResolver::Token token,
                           uint64_t stale, uint64_t pointer, DWORD64& out) -> bool {
        uint64_t resolved = 0;
        if (discoveryContext.outParams.value(token, resolved)) {
            out = resolved;
            ++inReplay;
            return true;
        }
        if (ttd::isPageGranular(stale)) {
            out = stale;
            return true;
        }
        if (!cursor.has_value()) cursor.emplace(discoveryContext.session.NewCursor());
        cursor->get()->SetPosition(deferred.retPos);
        if (resolveOutParam(discoveryContext.session, &*cursor, deferred.retPos, deferred.utid, pointer, deferred.width, out)) {
            ++postRun;
            return true;
        }
        return false;
    };

    for (auto const& deferred : this->m_deferred) {
        DWORD64 base = 0, size = 0;
        bool const haveBase = resolveHalf(deferred, deferred.baseToken, deferred.staleBase, deferred.pBase, base);
        bool const haveSize = resolveHalf(deferred, deferred.sizeToken, deferred.staleSize, deferred.pSize, size);

        if (haveBase && haveSize) {
            this->discoveredRegions.push_back({ base, size, deferred.protect });
            continue;
        }

        // Nothing recovered for one of the halves. The caller's own request is still on record
        // and the kernel's answer is that request rounded outward, so fall back to it rather
        // than dropping the region: an approximate region gets scanned, a dropped one never is.
        uint64_t approxBase = 0, approxSize = 0;
        if (this->approximateUnresolved() &&
            approximateFromRequest(deferred.staleBase, deferred.staleSize,
                                   haveBase, base, haveSize, size, approxBase, approxSize)) {
            ttdcapa::log::err() << std::format(
                "[!] [{}] Could not resolve {} for a deferred {} call; approximating it from the "
                "caller's request as {:#x}+{:#x}\n",
                ttd::positionToString(deferred.retPos),
                (!haveBase && !haveSize) ? "either out-param" : (!haveBase ? "the base address" : "the region size"),
                this->m_functionName, approxBase, approxSize
            );
            this->discoveredRegions.push_back({ approxBase, approxSize, deferred.protect });
            ++approximated;
            continue;
        }

        ttdcapa::log::err() << std::format(
            "[-] [{}] Could not resolve {} for a deferred {} call, skipping it! Base address: {:#x}({:#x}), Size: {:#x}({:#x})\n",
            ttd::positionToString(deferred.retPos),
            (!haveBase && !haveSize) ? "both out-params" : (!haveBase ? "the base address" : "the region size"),
            this->m_functionName, deferred.pBase, base, deferred.pSize, size
        );
        ++skipped;
    }

    // The first two counts are out-params (a call defers up to two), the last two are calls.
    ttdcapa::log::dbg() << std::format(
        "[+] Resolved {} deferred {} call(s): {} out-param(s) during the capture replay, "
        "{} post-run; {} call(s) approximated, {} skipped\n",
        this->m_deferred.size(), this->m_functionName, inReplay, postRun, approximated, skipped
    );

    this->m_deferred.clear();
}

size_t discovery::RegionProvider::mergeInto(DiscoveryContext& discoveryContext) {
    size_t added = 0;

    for (Region const& region : this->discoveredRegions) {
        if (!this->acceptRegion(discoveryContext, region)) continue;
        // addRegion rejects anything overlapping a region that is already tracked
        if (discoveryContext.regions.addRegion(region)) ++added;
    }

    return added;
}

void discovery::RegionProvider::finalize(DiscoveryContext& discoveryContext) {
    this->resolveDeferred(discoveryContext);
    size_t const tracked = this->mergeInto(discoveryContext);

    ttdcapa::log::dbg() << std::format("[+] Tracking {} {}(s)\n", tracked, this->m_trackedNoun);
}

bool discovery::NtMapViewOfSectionProvider::acceptRegion(DiscoveryContext& discoveryContext, Region const& region) {
    if (this->m_moduleRanges.empty()) {
        TTD::Replay::IReplayEngine* engine = discoveryContext.session.getEngine();
        size_t const count = engine->GetModuleLoadedEventCount();
        TTD::Replay::ModuleLoadedEvent const* moduleLoadEvents = engine->GetModuleLoadedEventList();

        this->m_moduleRanges.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            TTD::Replay::Module const* loadedModule = moduleLoadEvents[i].pModule;
            uint64_t const moduleBase = static_cast<uint64_t>(loadedModule->Address);
            this->m_moduleRanges.emplace_back(moduleBase, moduleBase + loadedModule->Size);
        }
    }

    for (auto const& [moduleBase, moduleEnd] : this->m_moduleRanges) {
        if (region.base < moduleEnd && moduleBase < region.end()) return false;
    }

    return true;
}

bool discovery::NtProtectVirtualMemoryProvider::acceptCall(ttd::FunctionCall const& functionCall) {
    uint32_t const newProtect = static_cast<uint32_t>(functionCall.Args[this->m_layout.protectArgIdx]);

    return (newProtect & ExecutableProtectionMask) != 0;  // only executable flips matter here
}

void discovery::NtProtectVirtualMemoryProvider::finalize(DiscoveryContext& discoveryContext) {
    this->resolveDeferred(discoveryContext);

    size_t reclassified = 0;
    for (Region const& protectEvent : this->discoveredRegions) {
        reclassified += discoveryContext.regions.reclassifyExecutable(protectEvent.base, protectEvent.size);
    }

    ttdcapa::log::dbg() << std::format("[+] Reclassified {} region(s) as executable via NtProtectVirtualMemory\n", reclassified);
}
