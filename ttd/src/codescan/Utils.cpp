#include "Utils.hpp"

#include "../log.hpp"

#include <format>
#include <string>
#include <windows.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

bool ttd::ReadMemory(TTD::Replay::UniqueCursor* cursor, TTD::GuestAddress read_address, uint64_t read_size, PVOID dest, TTD::Replay::QueryMemoryPolicy policy) {
    TTD::Replay::MemoryBuffer memorybuffer = cursor->get()->QueryMemoryBuffer(read_address, TTD::BufferView{ dest, read_size }, policy);
    return memorybuffer.Memory.Size == read_size;
}

bool ttd::ReadMemory(TTD::Replay::IThreadView const* thread, TTD::GuestAddress read_address, uint64_t read_size, PVOID dest) {
    TTD::Replay::MemoryBuffer memorybuffer = thread->QueryMemoryBuffer(read_address, TTD::BufferView{ dest, read_size });
    return memorybuffer.Memory.Size == read_size;
}

bool ttd::RecoverByReadback(
    ttd::TraceSession& session,
    TTD::Replay::Position const& from,
    TTD::Replay::UniqueThreadId threadId,
    TTD::GuestAddress address,
    uint64_t size,
    void* dst,
    uint64_t stepBudget
) {
    bool recovered = false;

    auto onRead = [&](TTD::Replay::ICursorView::MemoryWatchpointResult const&, TTD::Replay::IThreadView const* thread) -> bool {
        // The program is consuming these bytes right now, so its ThreadLocal view holds them
        TTD::Replay::MemoryBuffer buffer = thread->QueryMemoryBuffer(address, TTD::BufferView{ dst, size });
        recovered = (buffer.Memory.Size == size);

        return recovered;  // stop the replay as soon as the value is in hand
    };

    TTD::Replay::UniqueCursor cursor = session.NewCursor(from);
    cursor->AddMemoryWatchpoint(TTD::Replay::MemoryWatchpointData{
        .Address = address,
        .Size = size,
        .AccessMask = TTD::Replay::DataAccessMask::Read,
        .ThreadId = threadId,  // only the thread that made the call can read its own out-param
    });
    cursor->SetMemoryWatchpointCallback(onRead);
    cursor->SetEventMask(TTD::Replay::EventMask::MemoryWatchpoint);
    // Confining the replay to the calling thread keeps the step budget from being spent elsewhere
    cursor->SetReplayFlags(TTD::Replay::ReplayFlags::ReplayOnlyCurrentThread | TTD::Replay::ReplayFlags::ReplaySegmentsSequentially);
    cursor->SetPositionOnThread(threadId, from);
    cursor->ReplayForward(TTD::Replay::Position::Max, static_cast<TTD::Replay::StepCount>(stepBudget));

    return recovered;
}

ttd::StageTimer::StageTimer(char const* stageName)
    : m_stage(stageName)
    , m_started(std::chrono::steady_clock::now())
{}

ttd::StageTimer::~StageTimer() {
    auto const elapsed = std::chrono::steady_clock::now() - this->m_started;
    auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count();
    ttdcapa::log::dbg() << std::format("[+] {} took {} ms\n", this->m_stage, ms);
}

std::string ttd::positionToString(TTD::Replay::Position const& position) {
    return std::format(
        "{:x}:{:x}",
        static_cast<uint64_t>(position.Sequence),
        static_cast<uint64_t>(position.Steps)
    );
}

std::string wideToUTF8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), out.data(), needed, nullptr, nullptr);
    return out;
}
