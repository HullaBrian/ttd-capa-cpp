#include "TraceSession.hpp"
#include "Utils.hpp"

#include "../log.hpp"
#include "../ttdutils.hpp"

#include <iostream>
#include <format>
#include <stdexcept>
#include <winerror.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

ttd::TraceSession::TraceSession(std::wstring const& traceFilePath, bool rebuildUnloadableIndex) {
    ttdcapa::log::dbg() << "[+] Initializing TTD trace...\n";
    auto [engine, hr] = TTD::Replay::MakeReplayEngine();
    if (hr != S_OK || !engine) {
        throw std::runtime_error(std::format("[-] Failed to create TTD engine: {:#08X}", static_cast<uint32_t>(hr)));
    }

    this->engine = std::move(engine);
    if (!this->engine->Initialize(traceFilePath.c_str())) {
        throw std::runtime_error(std::format("[-] Failed to open trace file at {}", wideToUTF8(traceFilePath.c_str())));
    }

    // Shared with the call sweep, so a flag that repairs a stale index for one pass cannot
    // quietly do nothing for the other.
    ttdcapa::buildTraceIndex(this->engine, rebuildUnloadableIndex);
}

TTD::Replay::UniqueCursor ttd::TraceSession::NewCursor() {
    return this->NewCursor(this->engine->GetFirstPosition());
}

TTD::Replay::UniqueCursor ttd::TraceSession::NewCursor(TTD::Replay::Position position) {
    TTD::Replay::UniqueCursor cursor = TTD::Replay::UniqueCursor(this->engine->NewCursor());
    if (!cursor) {
        throw std::runtime_error("[-] Failed to create a trace cursor");
    }

    cursor->SetPosition(position);
    return cursor;
}

TTD::Replay::UniqueReplayEngine* ttd::TraceSession::getEnginePointer() {
    return &(this->engine);
}

TTD::Replay::IReplayEngine* ttd::TraceSession::getEngine() {
    return this->engine.get();
}
