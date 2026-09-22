#ifndef CODESCAN_DISCOVERYPASS_HPP
#define CODESCAN_DISCOVERYPASS_HPP

#include "CallCapturer.hpp"
#include "TraceSession.hpp"
#include "Region.hpp"
#include "RegionProviders.hpp"

#include <memory>
#include <vector>

namespace discovery {
    class DiscoveryPass {
        public:
            // Providers are finalized in registration order, so any provider that only reclassifies
            // regions (NtProtectVirtualMemory) has to be registered after the ones that add them
            template <typename TProvider>
            void addProvider(ttd::TraceSession& traceSession) {
                auto provider = std::make_unique<TProvider>();
                provider->registerBreakpoints(traceSession.getEnginePointer(), this->m_capturer);
                provider->setOutParamResolver(&this->m_outParams);
                this->m_RegionProviders.push_back(std::move(provider));
            }

            // One sequential replay to capture every watched call, then finalize each provider
            MemoryRegions run(ttd::TraceSession& traceSession);
        private:
            ttd::CallCapturer m_capturer;
            // Shared by every provider and by the capturer, so an out-param registered by one
            // provider's callback is retried against every later callback in the same replay
            ttd::OutParamResolver m_outParams;
            std::vector<std::unique_ptr<RegionProvider>> m_RegionProviders;
    };
}

#endif
