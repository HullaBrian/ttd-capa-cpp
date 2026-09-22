#ifndef CODESCAN_TRACESESSION_HPP
#define CODESCAN_TRACESESSION_HPP

#include <string>
#include <windows.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

namespace ttd {
    class TraceSession {
    public:
        // rebuildUnloadableIndex deletes a pre-existing index file that cannot be loaded and builds
        // a fresh one, instead of replaying without an index
        TraceSession(std::wstring const& traceFilePath, bool rebuildUnloadableIndex = false);

        // Creates a new TTD cursor sitting at the first position of the trace.
        // The cursor is owned by the caller and must not outlive the session.
        TTD::Replay::UniqueCursor NewCursor();
        // Creates a new TTD cursor at a specific TTD position
        TTD::Replay::UniqueCursor NewCursor(TTD::Replay::Position position);

        TTD::Replay::UniqueReplayEngine* getEnginePointer();
        TTD::Replay::IReplayEngine* getEngine();
    private:
        TTD::Replay::UniqueReplayEngine engine;
    };
}

#endif
