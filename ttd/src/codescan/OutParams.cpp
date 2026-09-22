#include "OutParams.hpp"

#include <algorithm>

using namespace ttd;

OutParamResolver::Token OutParamResolver::submit(TTD::Replay::UniqueThreadId utid, uint64_t address, uint32_t width) {
    if (address == 0 || width == 0 || width > sizeof(uint64_t)) return NoToken;

    uint32_t const thread = static_cast<uint32_t>(utid);

    // A newer call on the same slot wins; the older request is retired unresolved so it falls
    // back to the per-call path instead of picking up this call's answer.
    if (auto collision = this->m_liveByAddress.find(address); collision != this->m_liveByAddress.end()) {
        Token const stale = collision->second;
        for (auto& [otherThread, live] : this->m_liveByThread) {
            if (std::find(live.begin(), live.end(), stale) == live.end()) continue;
            this->retire(stale, otherThread);
            break;
        }
    }

    Token const token = this->m_pending.size();
    this->m_pending.push_back(Pending{ .address = address, .width = width });
    this->m_liveByThread[thread].push_back(token);
    this->m_liveByAddress[address] = token;
    ++this->m_outstanding;

    return token;
}

void OutParamResolver::retire(Token token, uint32_t utid) {
    auto it = this->m_liveByThread.find(utid);
    if (it != this->m_liveByThread.end()) {
        std::vector<Token>& live = it->second;
        // Order carries no meaning here, so drop by swapping the tail in.
        if (auto slot = std::find(live.begin(), live.end(), token); slot != live.end()) {
            *slot = live.back();
            live.pop_back();
        }
    }

    // Only clear the address entry if it still points at this token: a collision has already
    // repointed it at the newer request, which must stay live.
    uint64_t const address = this->m_pending[token].address;
    if (auto owner = this->m_liveByAddress.find(address);
        owner != this->m_liveByAddress.end() && owner->second == token) {
        this->m_liveByAddress.erase(owner);
    }

    --this->m_outstanding;
}

void OutParamResolver::retry(TTD::Replay::IThreadView const* thread) {
    if (this->m_outstanding == 0) return;  // the common case, one compare

    uint32_t const utid = static_cast<uint32_t>(thread->GetThreadInfo().UniqueId);
    auto it = this->m_liveByThread.find(utid);
    if (it == this->m_liveByThread.end() || it->second.empty()) return;

    // Walk backwards so retiring an entry (which swaps the tail in) cannot skip one.
    std::vector<Token>& live = it->second;
    for (size_t i = live.size(); i-- > 0;) {
        Token const token = live[i];
        Pending& pending = this->m_pending[token];

        uint64_t value = 0;
        TTD::Replay::MemoryBuffer buffer = thread->QueryMemoryBuffer(
            TTD::GuestAddress{ pending.address },
            TTD::BufferView{ &value, pending.width }
        );

        // The invariant, not a non-zero test: the caller's own pre-call store is readable here
        // too, and only page granularity tells the two apart.
        bool const got = buffer.Memory.Size == pending.width && isPageGranular(value);
        if (got) {
            pending.value = value;
            pending.resolved = true;
            ++this->m_resolved;
        }

        if (got || --pending.attemptsLeft == 0) this->retire(token, utid);
    }
}

bool OutParamResolver::value(Token token, uint64_t& out) const {
    if (token == NoToken || token >= this->m_pending.size()) return false;
    Pending const& pending = this->m_pending[token];
    if (!pending.resolved) return false;

    out = pending.value;
    return true;
}
