#include "CallCapturer.hpp"
#include "SymbolResolver.hpp"

#include "../log.hpp"

#include <algorithm>
#include <format>
#include <iostream>
#include <ranges>
#include <windows.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

void ttd::CallCapturer::AddBySymbol(TTD::Replay::UniqueReplayEngine* engine, std::wstring moduleName, std::string functionName, ttd::CallCapturer::Callback onReturn, size_t argCount) {
    size_t count = engine->get()->GetModuleLoadedEventCount();
    TTD::Replay::ModuleLoadedEvent const* moduleLoadEvents = engine->get()->GetModuleLoadedEventList();
    TTD::Replay::UniqueCursor cursor = TTD::Replay::UniqueCursor(engine->get()->NewCursor());
    cursor->SetPosition(engine->get()->GetFirstPosition());

    for (size_t i = 0; i < count; ++i) {
        TTD::Replay::ModuleLoadedEvent const& moduleLoadEvent = moduleLoadEvents[i];
        TTD::Replay::Module const* loadedModule = moduleLoadEvent.pModule;

        // Traces record the full path a module was loaded from, with whatever casing the
        // loader used, so match on the base name case-insensitively instead
        wchar_t const* baseName = TTD::Replay::GetModuleBaseName(loadedModule->pName, loadedModule->NameLength);
        if (_wcsicmp(baseName, moduleName.c_str()) != 0) continue;

        cursor->SetPosition(moduleLoadEvent.Position);
        bool is64 = true;
        TTD::GuestAddress functionAddress = ttd::ResolveExport(&cursor, loadedModule->Address, functionName.c_str(), &is64);
        if (functionAddress == TTD::GuestAddress::Null) {
            ttdcapa::log::err() << std::format("[-] Could not resolve the export {}\n", functionName);
            continue;
        }

        this->Add(functionAddress, onReturn, argCount, is64);
        ttdcapa::log::dbg() << std::format("    [+] Watching {} @ {:#x} ({}-bit)\n", functionName,
                                           static_cast<uint64_t>(functionAddress), is64 ? 64 : 32);
    }
}

void ttd::CallCapturer::Add(TTD::GuestAddress address, ttd::CallCapturer::Callback onReturn, size_t argCount, bool is64) {
    this->m_functionBreakpoints[static_cast<uint64_t>(address)] = Breakpoint{ std::move(onReturn), argCount, is64 };
}

void ttd::CallCapturer::Run(TTD::Replay::ICursorView* cursor) {
    this->m_pending.clear();
    cursor->SetCallReturnCallback(*this);
    cursor->SetIndirectJumpCallback(*this);

    // Everything replays sequentially on one thread so the callbacks stay ordered
    cursor->SetReplayFlags(TTD::Replay::ReplayFlags::ReplayAllSegmentsWithoutFiltering | TTD::Replay::ReplayFlags::ReplaySegmentsSequentially);

    cursor->SetPosition(TTD::Replay::Position::Min);
    cursor->ReplayForward();
}

void ttd::CallCapturer::CaptureArgs(std::vector<uint64_t>& pCapturedArgs, size_t argCount, bool is64, TTD::Replay::IThreadView const* pThread) {
    pCapturedArgs.clear();
    pCapturedArgs.reserve(argCount);

    TTD::Replay::RegisterContext registers = pThread->GetCrossPlatformContext();

    if (!is64) {
        // stdcall: nothing arrives in registers, and at the callee's first instruction
        // ESP points at the return address, so the arguments begin one word above it.
        X86_NT5_CONTEXT const* ctx = reinterpret_cast<X86_NT5_CONTEXT const*>(&registers);

        std::vector<uint32_t> stackArgs(argCount, 0);
        pThread->QueryMemoryBuffer(
            TTD::GuestAddress{ static_cast<uint64_t>(ctx->Esp) + 4 },
            TTD::BufferView{ stackArgs.data(), argCount * sizeof(uint32_t) }
        );
        for (uint32_t a : stackArgs) {
            pCapturedArgs.push_back(a);
        }
        return;
    }

    AMD64_CONTEXT const* ctx = reinterpret_cast<AMD64_CONTEXT const*>(&registers);

    uint64_t const regArgs[4] = { ctx->Rcx, ctx->Rdx, ctx->R8, ctx->R9 };
    size_t const registerCount = (argCount < 4) ? argCount : 4;
    for (size_t i = 0; i < registerCount; ++i) {
        pCapturedArgs.push_back(regArgs[i]);
    }

    // Capture arguments off the stack
    if (argCount > 4) {
        size_t stackCount = argCount - 4;
        std::vector<uint64_t> stackArgs(stackCount, 0);
        pThread->QueryMemoryBuffer(
            TTD::GuestAddress{ ctx->Rsp + 0x28 },
            TTD::BufferView{ stackArgs.data(), stackCount * sizeof(uint64_t) }
        );
        for (uint64_t a : stackArgs) {
            pCapturedArgs.push_back(a);
        }
    }
}

// Indirect jumps to breakpointed functions
void ttd::CallCapturer::operator()(TTD::GuestAddress callTargetAddress, TTD::Replay::IThreadView const* thread) {
    // Before the breakpoint filter: these callbacks fire on every call in the trace, and that
    // volume is exactly what makes the out-param read-backs cheap to catch.
    if (this->m_outParams != nullptr) this->m_outParams->retry(thread);

    auto breakpoint = this->m_functionBreakpoints.find(static_cast<uint64_t>(callTargetAddress));
    if (breakpoint == this->m_functionBreakpoints.end()) return;

    TTD::Replay::RegisterContext regs = thread->GetCrossPlatformContext();
    bool const is64 = breakpoint->second.Is64;

    // Read [rsp]/[esp] for return address. It is a guest pointer, so reading a 64-bit
    // one on a 32-bit guest would splice the caller's next stack slot onto it and never
    // match the address the ret reports.
    uint64_t retAddr = 0;
    uint64_t const stackPointer = is64
        ? reinterpret_cast<AMD64_CONTEXT const*>(&regs)->Rsp
        : static_cast<uint64_t>(reinterpret_cast<X86_NT5_CONTEXT const*>(&regs)->Esp);
    thread->QueryMemoryBuffer(
        TTD::GuestAddress{ stackPointer },
        TTD::BufferView{ &retAddr, is64 ? sizeof(uint64_t) : sizeof(uint32_t) }
    );
    if (retAddr == 0) return; // can't recover the return address

    uint32_t utid = static_cast<uint32_t>(thread->GetThreadInfo().UniqueId);
    PendingCall pending{};
    pending.ReturnToAddr = retAddr;
    pending.Call.FunctionAddress = callTargetAddress;
    pending.Call.Utid = thread->GetThreadInfo().UniqueId;
    pending.Call.EntryPosition = thread->GetPosition();
    pending.Call.Is64 = is64;

    CaptureArgs(pending.Call.Args, breakpoint->second.Args, is64, thread);

    m_pending[utid].push_back(std::move(pending));
}

// Direct calls / returns to breakpointed functions
void ttd::CallCapturer::operator()(TTD::GuestAddress callTargetAddress, TTD::GuestAddress fallThrough, TTD::Replay::IThreadView const* thread) {
    if (this->m_outParams != nullptr) this->m_outParams->retry(thread);

    bool isRet = (static_cast<uint64_t>(fallThrough) == 0);
    bool isCall = !isRet;
    uint32_t utid = static_cast<uint32_t>(thread->GetThreadInfo().UniqueId);

    if (isCall) {
        auto breakpoint = this->m_functionBreakpoints.find(static_cast<uint64_t>(callTargetAddress));
        if (breakpoint == this->m_functionBreakpoints.end()) return;

        PendingCall pending{};
        pending.ReturnToAddr = static_cast<uint64_t>(fallThrough);
        pending.Call.FunctionAddress = callTargetAddress;
        pending.Call.Utid = thread->GetThreadInfo().UniqueId;
        pending.Call.EntryPosition = thread->GetPosition();
        pending.Call.Is64 = breakpoint->second.Is64;
        CaptureArgs(pending.Call.Args, breakpoint->second.Args, breakpoint->second.Is64, thread);

        m_pending[utid].push_back(std::move(pending));
    } else {
        auto stackIt = m_pending.find(utid);
        if (stackIt == m_pending.end() || stackIt->second.empty())
            return;

        // Search stack for matching return address
        auto& stack = stackIt->second;
        uint64_t returnedTo = static_cast<uint64_t>(callTargetAddress);
        for (int i = static_cast<int>(stack.size()) - 1; i >= 0; i--) {
            if (stack[i].ReturnToAddr != returnedTo)
                continue;

            stack[i].Call.ReturnPosition = thread->GetPosition();
            stack[i].Call.ReturnValue = thread->GetBasicReturnValue();

            try {
                uint64_t funcAddr = static_cast<uint64_t>(stack[i].Call.FunctionAddress);
                auto it = this->m_functionBreakpoints.find(funcAddr);
                if (it != this->m_functionBreakpoints.end())
                    it->second.OnReturn(stack[i].Call, thread);
            } catch (const std::exception& e) {
                ttdcapa::log::err() << "[-] Error when attempting to call memory region provider callback: " << e.what() << "\n";
            }

            stack.erase(stack.begin() + i);
            break;
        }
    }
}
