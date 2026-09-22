#ifndef CODESCAN_OUTPARAMS_HPP
#define CODESCAN_OUTPARAMS_HPP

#include <cstdint>
#include <unordered_map>
#include <vector>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

namespace ttd {
    // The memory syscalls round the caller's request to pages before writing it back, so a base
    // or size that is not page-granular provably did not come from the kernel -- it is the value
    // the caller left in the slot before the call. This is the invariant that separates "the
    // kernel's answer" from "the caller's request", which a non-zero test cannot do: a wrapper
    // that pre-writes its requested size hands that request back to any query, silently, and the
    // region is then reconstructed a page or more short.
    inline bool isPageGranular(uint64_t value) { return value != 0 && (value % 0x1000) == 0; }

    // Recovers syscall out-params the kernel wrote, from inside the replay that captured the call.
    //
    // The kernel's write to `PVOID* BaseAddress` is not a recorded write event, so at the `ret`
    // the calling thread's ThreadLocal view still holds whatever the caller put there. The value
    // only enters the trace when the guest reads it back -- and the capture replay keeps calling
    // callbacks on that same thread as it rolls past the syscall. So rather than saving the slot
    // to chase afterwards with a seek and a bounded replay per value, register it here and retry
    // it on each subsequent callback for that thread: the read-back arrives on its own, inside the
    // pass that is already running, for the cost of a query.
    class OutParamResolver {
    public:
        using Token = size_t;
        static constexpr Token NoToken = static_cast<Token>(-1);

        // Registers `address` as an out-param slot to watch on `utid`'s subsequent callbacks.
        // `width` is the guest's pointer width in bytes: the slot holds a PVOID or a SIZE_T,
        // and reading eight bytes of a four-byte one splices the neighbouring dword into the
        // value -- which then fails the page-granularity test and looks like "never resolved"
        // rather than like the bug it is.
        // Any live request on the same address is retired first: wrappers reuse one stack local
        // for every call they make, and without this an earlier call reads back a later call's
        // base address. That failure does not lose a region, it invents a wrong one, which then
        // overlaps a real region and displaces it -- so the retired request falls back to the
        // per-call path rather than being allowed to guess.
        //
        // Note what this does NOT cover: the collision rule only fires when another *watched*
        // syscall claims the slot. Unrelated code reusing the same stack frame is invisible to
        // it, so the real guard against picking up a stranger's value is that the value must be
        // page-granular (a 4 KiB-aligned quantity is not what an arbitrary reused local holds),
        // backed by the attempt bound below. Widening MaxAttempts weakens that; it is a window,
        // not a search.
        Token submit(TTD::Replay::UniqueThreadId utid, uint64_t address, uint32_t width = sizeof(uint64_t));

        // Retries every live request belonging to this thread. Called from the capture callbacks,
        // so it must stay cheap: one integer compare when there is nothing outstanding.
        void retry(TTD::Replay::IThreadView const* thread);

        // True once the retry loop has caught a page-granular value for this token.
        bool value(Token token, uint64_t& out) const;

        size_t submitted() const { return this->m_pending.size(); }
        size_t resolved() const { return this->m_resolved; }

    private:
        // How many of the thread's later callbacks a request is retried across. A few hundred is
        // a short window in trace terms -- the read-back is normally the caller's next few
        // instructions -- and past it the slot may well belong to something else.
        static constexpr uint32_t MaxAttempts = 512;

        struct Pending {
            uint64_t address = 0;
            uint64_t value = 0;
            uint32_t width = sizeof(uint64_t);  // bytes to read: the guest's pointer width
            uint32_t attemptsLeft = MaxAttempts;
            bool resolved = false;
        };

        void retire(Token token, uint32_t utid);

        std::vector<Pending> m_pending;
        // Live (not yet resolved or expired) tokens per thread, which is the only set the hot
        // path walks.
        std::unordered_map<uint32_t, std::vector<Token>> m_liveByThread;
        // Live token per slot address, for the retire-on-collision rule above.
        std::unordered_map<uint64_t, Token> m_liveByAddress;
        size_t m_outstanding = 0;
        size_t m_resolved = 0;
    };
}

#endif
