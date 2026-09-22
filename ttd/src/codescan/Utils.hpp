#ifndef CODESCAN_UTILS_HPP
#define CODESCAN_UTILS_HPP

#include "TraceSession.hpp"

#include <chrono>
#include <string>
#include <windows.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

// Small TTD helpers shared by the code-scan subsystem: memory reads against a cursor or a
// callback's thread view, readback recovery for bytes no query can see, and position
// formatting.
namespace ttd {
    bool ReadMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress read_address, uint64_t read_size, PVOID dst,
        TTD::Replay::QueryMemoryPolicy policy = TTD::Replay::QueryMemoryPolicy::Default);
    // Same read against the thread view handed to a callback (always ThreadLocal)
    bool ReadMemory(TTD::Replay::IThreadView const* thread, TTD::GuestAddress read_address, uint64_t read_size, PVOID dst);

    // Recovers bytes no memory query at 'from' can see, by replaying the given thread forward until
    // the program reads them back. Queries only reach what the engine attributes to the queried
    // position's fragment, whereas the read that consumes a value is recorded wherever it happens.
    // Bounded by a step budget, since a stack slot read far enough ahead belongs to a later variable.
    bool RecoverByReadback(
        TraceSession& session,
        TTD::Replay::Position const& from,
        TTD::Replay::UniqueThreadId threadId,
        TTD::GuestAddress address,
        uint64_t size,
        void* dst,
        uint64_t stepBudget
    );

    // Renders "<sequence>:<steps>" in lowercase hex, matching what WinDbg's !tt takes.
    std::string positionToString(TTD::Replay::Position const& position);

    // Wall-clock for one stage, reported to the log when it goes out of scope.
    //
    // Replay passes dominate everything else on a large recording, and the way a tool ends up
    // slow is doing one pass per item without that ever being a deliberate decision. Timing the
    // stage boundaries is what makes that visible -- so these lines exist to be read, not just
    // to decorate the output: if one stage grows with the region count, it is replaying per
    // region again.
    class StageTimer {
    public:
        explicit StageTimer(char const* stageName);
        ~StageTimer();
        StageTimer(StageTimer const&) = delete;
        StageTimer& operator=(StageTimer const&) = delete;

    private:
        char const* m_stage;
        std::chrono::steady_clock::time_point m_started;
    };
}

std::string wideToUTF8(const std::wstring& wstr);

#endif
