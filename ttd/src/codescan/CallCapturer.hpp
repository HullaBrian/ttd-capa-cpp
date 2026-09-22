#ifndef CODESCAN_CALLCAPTURER_HPP
#define CODESCAN_CALLCAPTURER_HPP

#include "OutParams.hpp"

#include <cassert>
#include <functional>
#include <unordered_map>
#include <windows.h>
#include <vector>
#include <tuple>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>
#include <TTD/IReplayEngineRegisters.h>

namespace ttd {
    struct FunctionCall {
        TTD::GuestAddress FunctionAddress;
        TTD::Replay::UniqueThreadId Utid;
        TTD::Replay::Position EntryPosition;   // Timestamp of call/jmp instruction
        TTD::Replay::Position ReturnPosition;  // Timestamp of ret instruction
        std::vector<uint64_t> Args;  // Arguments passed to function. Size is the argument count passed to Add()
        uint64_t ReturnValue;
        // Bitness of the module the callee lives in, which is what decided where the
        // arguments above were read from -- and what a caller dereferencing one of them
        // needs, since a 32-bit guest's out-params are 4 bytes wide, not 8. A WoW64
        // process has both widths of ntdll loaded, so this is per breakpoint rather
        // than per trace.
        bool Is64 = true;
    };

    class CallCapturer {
        public:
            using UniqueThreadID = uint32_t;
            using ArgumentCount = size_t;
            using Callback = std::function<void(FunctionCall const&, TTD::Replay::IThreadView const*)>;

            // Adds 1+ breakpoint(s) given a module name and function name. Captures argCount
            // arguments, decoded for the bitness of whichever image the export was found in --
            // in a WoW64 trace the same module name resolves twice, once in each width.
            void AddBySymbol(TTD::Replay::UniqueReplayEngine* engine, std::wstring moduleName, std::string functionName, Callback onReturn, size_t argCount);
            // Adds a new function breakpoint given a callback function and number of arguments to capture
            void Add(TTD::GuestAddress address, Callback onReturn, size_t argCount, bool is64 = true);
            // Runs a cursor sequentially on a trace to capture all calls to breakpointed functions
            void Run(TTD::Replay::ICursorView* cursor);

            // Out-param requests registered by the callbacks are retried against every later
            // callback on the same thread, so values the kernel wrote resolve inside this replay
            // instead of costing a seek and a bounded replay each afterwards. Set before Run().
            void SetOutParamResolver(OutParamResolver* resolver) { this->m_outParams = resolver; }

            // Indirect jumps to breakpointed functions
            void operator()(TTD::GuestAddress callTargetAddress, TTD::Replay::IThreadView const* thread);
            // Direct calls to breakpointed functions
            void operator()(TTD::GuestAddress callTargetAddress, TTD::GuestAddress fallThrough, TTD::Replay::IThreadView const* thread);
        private:
            struct PendingCall {
                uint64_t ReturnToAddr;  // fallThrough addr at call time = return address
                FunctionCall Call;
            };

            // One watched function: what to call at its return, how many arguments to read,
            // and which calling convention to read them under.
            struct Breakpoint {
                Callback OnReturn;
                ArgumentCount Args = 0;
                bool Is64 = true;
            };

            // Capture up to argCount arguments, from registers and the stack on x64 or
            // entirely from the stack on x86
            static void CaptureArgs(std::vector<uint64_t>& pCapturedArgs, size_t argCount, bool is64, TTD::Replay::IThreadView const* thread);
            // Maps breakpoint address to what to do when it is hit
            std::unordered_map<uint64_t, Breakpoint> m_functionBreakpoints;
            // Maps every thread ID to a list of pending calls
            std::unordered_map<UniqueThreadID, std::vector<PendingCall>> m_pending;
            // Optional; null means out-params are left entirely to the post-run path
            OutParamResolver* m_outParams = nullptr;
    };
}

#endif
