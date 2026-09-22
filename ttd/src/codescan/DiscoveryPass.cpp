#include "TraceSession.hpp"
#include "Region.hpp"
#include "RegionProviders.hpp"
#include "DiscoveryPass.hpp"
#include "Utils.hpp"

#include "../log.hpp"

#include <format>
#include <iostream>
#include <memory>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>
#include <TTD/IReplayEngineRegisters.h>

using namespace discovery;

MemoryRegions DiscoveryPass::run(ttd::TraceSession& traceSession) {
    MemoryRegions regionSet;

    ttdcapa::log::dbg() << "[+] Tracing memory allocations...\n";
    {
        // Replay 1 of 2 in the code-scan pipeline: capture every watched call. The out-param
        // resolver rides along on this pass, so recovery costs no replay of its own.
        ttd::StageTimer timer("Capture replay");
        TTD::Replay::UniqueCursor cursor = traceSession.NewCursor();
        this->m_capturer.SetOutParamResolver(&this->m_outParams);
        this->m_capturer.Run(cursor.get());
    }

    ttdcapa::log::dbg() << std::format(
        "[+] Recovered {}/{} out-param(s) during the capture replay\n",
        this->m_outParams.resolved(), this->m_outParams.submitted()
    );

    ttdcapa::log::dbg() << "[+] Resolving memory regions...\n";
    {
        // Near-free while the resolver answers everything; a stage that starts costing seconds
        // again means out-params are expiring and falling back to a replay apiece.
        ttd::StageTimer timer("Region resolution");
        DiscoveryContext discoveryContext{ traceSession, regionSet, this->m_outParams };
        for (auto& provider : this->m_RegionProviders) {
            provider->finalize(discoveryContext);
        }
    }

    ttdcapa::log::err() << std::format("[+] Tracking {} memory region(s)\n", regionSet.size());

    return regionSet;
}
