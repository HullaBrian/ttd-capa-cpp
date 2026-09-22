#include "extract.hpp"

#include "abi.hpp"
#include "log.hpp"
#include "ttdutils.hpp"
#include "win32meta.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>  // S_OK, HRESULT

#include <TTD/IReplayEngineStl.h>
#include <TTD/IReplayEngineRegisters.h>
#include <TTD/ErrorReporting.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ttdcapa {
    namespace {
        // Calls whose return we haven't seen yet, per thread. Each carries the [Out]
        // dereferences we deliberately postponed until the callee has run, and the [In]
        // strings the entry could not read.
        struct InFlight {
            uint64_t ret_addr = 0;
            size_t call_index = 0;
            GuestArch arch = GuestArch::X64;  // must match the entry pass to re-read correctly
            std::vector<PendingOut> pending;
            // Parameters the metadata types as strings that read back as nothing at the
            // call. The thread view a callback gets answers at ThreadLocal fidelity and
            // accumulates as the replay runs, so a buffer this thread had not touched yet
            // is invisible at the entry and visible later -- and a callee that reads its
            // own string argument, which is the normal reason to pass one, is exactly what
            // makes it visible. By the return we are standing past that read, on the same
            // thread, with the same view, and ask again for the cost of a read.
            std::vector<uint16_t> unread_strings;
        };

        // How many call/return events pass between cancellation checks. Calling into the
        // host's predicate on every event would show up in the sweep's cost on a trace with
        // millions of them, and a fraction of a second of extra latency on cancel is fine.
        constexpr uint64_t kCancelPollInterval = 8192;

        std::string formatPosition(TTD::Replay::Position const& position) {
            char buffer[40];
            std::snprintf(buffer, sizeof(buffer), "%llX:%llX",
                          static_cast<unsigned long long>(position.Sequence),
                          static_cast<unsigned long long>(position.Steps));
            return buffer;
        }

        // The inverse, for the recovery pass: it navigates back to positions the sweep
        // already wrote down rather than carrying a second copy of every one of them
        // through a report that holds millions of calls.
        bool parsePosition(std::string const& text, TTD::Replay::Position& out) {
            size_t const colon = text.find(':');
            if (colon == std::string::npos) {
                return false;
            }
            char* end = nullptr;
            unsigned long long const seq = std::strtoull(text.c_str(), &end, 16);
            if (end != text.c_str() + colon) {
                return false;
            }
            unsigned long long const steps = std::strtoull(text.c_str() + colon + 1, &end, 16);
            if (end == text.c_str() + colon + 1) {
                return false;
            }
            out = TTD::Replay::Position{ static_cast<TTD::SequenceId>(seq),
                                         static_cast<TTD::Replay::StepCount>(steps) };
            return true;
        }

        // One string parameter the sweep could not read, and where to stand to try again.
        struct StringMiss {
            uint64_t sequence = 0;  // sort key: seek the cursor forward, never backwards
            uint64_t steps = 0;
            size_t call_index = 0;
            uint16_t param_index = 0;
            bool at_return = false;  // the position above is the call's return, not the call
        };

        // What the recovery pass settled, and whether the host stopped it partway. The count
        // alone cannot say: a pass that recovered nothing and one cancelled before its first
        // seek both report zero, and only one of them produced a complete report.
        struct Recovery {
            size_t recovered = 0;
            bool cancelled = false;
        };

        // Re-read the string parameters the sweep's thread view could not see.
        //
        // The sweep reads arguments inside a call/return callback, where the only memory
        // view available answers at ThreadLocal fidelity: it knows what this thread
        // touched near this position and little else. A caller's string argument sitting
        // in a heap buffer filled long before the call is invisible there, so the report
        // would show the pointer and drop the string -- and capa, which matches on the
        // string, would never see it either. The bytes are in the trace the whole time; a
        // cursor parked at the same position and asked at GloballyConservative returns
        // them. So collect the misses during the sweep and settle them here, in one
        // forward pass over the trace rather than a seek per call.
        Recovery recoverMissedStrings(TTD::Replay::UniqueReplayEngine& engine,
                                      DecodeOptions const& opt, Report& out,
                                      std::function<bool()> const& cancelled) {
            std::vector<StringMiss> misses;
            for (size_t ci = 0; ci < out.process.calls.size(); ++ci) {
                CallRecord const& call = out.process.calls[ci];
                if (!call.metadata) {
                    continue;  // heuristic capture has no parameter types to trust
                }
                for (size_t pi = 0; pi < call.params.size(); ++pi) {
                    DecodedArg const& arg = call.params[pi];
                    if (!isPlainStringKind(arg.kind) || arg.has_str
                        || arg.raw < kMinStringAddr) {
                        continue;  // MAKEINTRESOURCE-style ids and null land here
                    }
                    // An [Out] string is only populated once the callee has run, so the
                    // return is where it was read and where it has to be read again. When
                    // there is no return position the call never returned -- still in flight
                    // at the end of the trace, the process died inside it, or the return went
                    // unmatched -- and the call position is the one place that buffer is
                    // guaranteed *not* to hold the callee's output. Reading there anyway
                    // would record whatever the buffer held from its previous use and file it
                    // as the out-parameter's value, so skip it: an unread parameter is
                    // honest, a stale one is not.
                    //
                    // This also skips an [In,Out] string on a never-returning call, where the
                    // caller's input really is at the call position and could legitimately be
                    // read. DecodedArg records is_out and has no is_in, so the two cannot be
                    // told apart here; the loss is a handful of parameters per trace (25 of
                    // 91,455 calls on beacon_x6401 never returned) and the alternative is a
                    // wrong value.
                    if (arg.is_out && call.return_position.empty()) {
                        continue;
                    }
                    std::string const& where =
                        arg.is_out ? call.return_position : call.position;
                    TTD::Replay::Position pos;
                    if (!parsePosition(where, pos)) {
                        continue;
                    }
                    misses.push_back(StringMiss{ static_cast<uint64_t>(pos.Sequence),
                                                 static_cast<uint64_t>(pos.Steps), ci,
                                                 static_cast<uint16_t>(pi), arg.is_out });
                }
            }
            if (misses.empty()) {
                return Recovery{};
            }

            std::sort(misses.begin(), misses.end(), [](StringMiss const& a, StringMiss const& b) {
                return a.sequence != b.sequence ? a.sequence < b.sequence : a.steps < b.steps;
            });

            log::dbg() << "[+] Recovering " << misses.size()
                       << " string parameter(s) the sweep could not read...\n";

            TTD::Replay::UniqueCursor cursor{ engine->NewCursor() };
            MemorySource const src{ cursor.get(),
                                    TTD::Replay::QueryMemoryPolicy::GloballyConservative };

            Recovery result;
            std::vector<size_t> changed;
            uint64_t last_seq = ~0ull, last_steps = ~0ull;
            for (size_t i = 0; i < misses.size(); ++i) {
                // Polled every iteration, not on the sweep's kCancelPollInterval. That
                // interval is sized for the millions of events a sweep sees; this loop runs
                // over misses, of which there are hundreds, so any interval wider than one
                // fires only at i == 0 and leaves every seek after it uninterruptible. This
                // is also the seek-bound part of extraction -- the part a host most wants to
                // be able to stop -- and one std::function call is nothing beside a loop body
                // that seeks the trace.
                if (cancelled && cancelled()) {
                    result.cancelled = true;
                    break;
                }
                StringMiss const& miss = misses[i];
                if (miss.sequence != last_seq || miss.steps != last_steps) {
                    // A seek, not a ReplayForward to the same place: the misses are
                    // sorted so this only ever moves forward, and measured on a 75 MB
                    // trace the two cost the same (22.3s vs 22.6s for 1673 positions),
                    // so there is nothing to buy by replaying the gap.
                    cursor->SetPosition(
                        TTD::Replay::Position{ static_cast<TTD::SequenceId>(miss.sequence),
                                               static_cast<TTD::Replay::StepCount>(miss.steps) });
                    last_seq = miss.sequence;
                    last_steps = miss.steps;
                }
                CallRecord& call = out.process.calls[miss.call_index];
                DecodedArg& arg = call.params[miss.param_index];
                if (recoverString(src, opt, arg)) {
                    // Where the read happened is part of the answer: an [Out] parameter was
                    // read past the callee's write, and a consumer that cannot tell a
                    // pre-call value from a post-call one will attribute it to the wrong
                    // moment. recoverString does not set this itself because it is also used
                    // for [In] parameters read at the call, where it must stay false.
                    arg.from_return = miss.at_return;
                    ++result.recovered;
                    changed.push_back(miss.call_index);
                }
            }

            // capa matches against `args`, not `params`, so a string recovered here is
            // only evidence once it lands there too. Rebuild each touched call once.
            std::sort(changed.begin(), changed.end());
            changed.erase(std::unique(changed.begin(), changed.end()), changed.end());
            for (size_t ci : changed) {
                CallRecord& call = out.process.calls[ci];
                call.args = toCapaArgs(call.params);
            }
            return result;
        }
    }  // namespace

    Status extractReport(ExtractConfig const& config, Report& out) {
        if (config.trace.empty()) return Status::InvalidArgument;

        DecodeOptions decode_opt;
        decode_opt.max_buffer = config.max_buffer;
        if (!config.no_metadata) {
            std::string err;
            if (win32meta::loadIndex(config.win32_index, err)) {
                log::dbg() << "[+] Loaded Win32 metadata for " << win32meta::index().functionCount()
                           << " functions\n";
            } else {
                log::err() << "[!] " << err << "; falling back to heuristic argument capture\n";
            }
        }

        auto [engine, hr] = TTD::Replay::MakeReplayEngine();
        if (hr != S_OK || !engine) {
            log::err() << "[-] Failed to create replay engine: 0x" << std::hex << hr << std::dec << "\n";
            return Status::EngineFailed;
        }

        // A failed Initialize leaves the engine with no trace behind it, so every subsequent
        // query reads back zeroes -- stop here rather than emitting a confidently empty report.
        if (!initializeTTDEngine(engine, config.trace.wstring(), config.rebuild_index)) {
            return Status::EngineFailed;
        }

        out.trace_path = config.trace;
        // Deliberately not gated on sys.System.ProcessorArchitecture: that field comes from
        // GetSystemInfo() on the recording machine, so a 32-bit process recorded on an x64 box
        // reports AMD64. The guest's real width comes from each module's PE header while
        // resolving exports, below.
        TTD::SystemInfo const& sys = engine->GetSystemInfo();
        out.process.pid = static_cast<uint64_t>(sys.ProcessId);

        TTD::Replay::UniqueCursor inspection_cursor{ engine->NewCursor() };

        // File-scope facts: hashes, imports/exports/sections, strings, and the thread list.
        // This is also what settles the trace's architecture, from the main module's PE
        // headers -- the only place the *guest's* width is recorded.
        initializeReport(out, engine, inspection_cursor, config.sample.wstring());

        // x86 and x64 are the two conventions decodeArgs knows. An ARM64 trace would
        // otherwise be read as x64 all the way through -- registers reinterpreted from a
        // context that never held them -- and produce a confidently wrong report rather
        // than an error.
        if (out.arch != "x86" && out.arch != "x64") {
            log::err() << "[-] Unsupported trace architecture: " << out.arch << "\n";
            return Status::UnsupportedArch;
        }

        std::unordered_map<uint64_t, ResolvedExport> exports =
            resolveTraceModuleExports(engine, inspection_cursor);
        size_t exports32 = 0;
        for (auto const& entry : exports) {
            if (!entry.second.is64) ++exports32;
        }
        log::dbg() << "[+] Resolved " << exports.size()
                   << " exported module functions across execution ("
                   << exports32 << " in 32-bit modules)\n";

        std::unordered_map<uint64_t, std::vector<InFlight>> in_flight;
        uint64_t seq = 0;
        uint64_t events_seen = 0;
        size_t strings_at_return = 0;  // strings the entry missed and the return recovered
        bool limit_hit = false;
        bool cancelled = false;

        TTD::Replay::UniqueCursor sweep{ engine->NewCursor() };

        auto on_call_return = [&](TTD::GuestAddress target, TTD::GuestAddress fall_through,
                                  TTD::Replay::IThreadView const* thread) noexcept {
            bool const is_call = (static_cast<uint64_t>(fall_through) != 0);
            uint64_t const utid = static_cast<uint64_t>(thread->GetThreadInfo().UniqueId);
            ++events_seen;

            if (config.cancelled && (events_seen % kCancelPollInterval) == 0 && config.cancelled()) {
                cancelled = true;
                sweep->InterruptReplay();
                return;
            }

            if (is_call) {
                auto it = exports.find(static_cast<uint64_t>(target));
                if (it == exports.end()) {  // not a resolved API entry point
                    return;
                }
                if (config.max_calls != 0 && out.process.calls.size() >= config.max_calls) {
                    limit_hit = true;
                    return;
                }

                CallRecord rec;
                rec.tid = utid;
                rec.seq = seq++;
                rec.module = it->second.module;
                rec.api = it->second.api;
                rec.position = formatPosition(thread->GetPosition());

                TTD::Replay::RegisterContext regs = thread->GetCrossPlatformContext();
                auto const* ctx = reinterpret_cast<AMD64_CONTEXT const*>(&regs);

                // The target module's PE header decided this; in a WoW64 trace the
                // 32-bit and 64-bit halves alternate call by call.
                CallFrame frame;
                frame.arch = it->second.is64 ? GuestArch::X64 : GuestArch::X86;
                frame.thread = thread;
                if (frame.arch == GuestArch::X64) {
                    frame.x64 = ctx;
                } else {
                    frame.x86 = reinterpret_cast<X86_NT5_CONTEXT const*>(&regs);
                }

                std::vector<PendingOut> pending;
                std::vector<uint16_t> unread_strings;
                win32meta::FuncSig const* sig = win32meta::index().lookup(rec.api);
                // decodeArgs declines a signature it cannot lay out for this
                // architecture, in which case the heuristic path below is still
                // better than parameters read from the wrong offsets.
                if (sig != nullptr && !sig->unsupported()
                    && decodeArgs(*sig, frame, decode_opt, rec.params, pending)) {
                    // We know the real arity, so capture exactly that many arguments
                    // -- no stale RDX/R8/R9 residue masquerading as parameters.
                    rec.args = toCapaArgs(rec.params);
                    rec.metadata = true;
                    // [Out] is deliberately excluded: decodeArgs already deferred every
                    // [Out] pointer above kMinDerefAddr into `pending`, which is the same
                    // threshold as kMinStringAddr, so an [Out] string listed here would be
                    // read a second time at the return by resolvePendingOuts -- from the
                    // same view, at the same position, through the same readAnsiString --
                    // and immediately overwritten with the identical answer. That was 1,103
                    // duplicated string reads of 2,400 on beacon_x6401, and it also made
                    // the count below report those parameters as recoveries this mechanism
                    // was responsible for when the [Out] pass had them covered either way.
                    for (size_t pi = 0; pi < rec.params.size(); ++pi) {
                        DecodedArg const& p = rec.params[pi];
                        if (isPlainStringKind(p.kind) && !p.has_str && !p.is_out
                            && p.raw >= kMinStringAddr) {
                            unread_strings.push_back(static_cast<uint16_t>(pi));
                        }
                    }
                } else {
                    rec.params.clear();
                    pending.clear();
                    unread_strings.clear();

                    if (frame.arch == GuestArch::X86) {
                        // Nothing arrives in registers on x86, so the heuristic has to
                        // read the stack even without --with-stack-args. Four words
                        // keeps it comparable to the x64 fallback's four registers.
                        int const words = config.with_stack_args ? 8 : 4;
                        for (int k = 0; k < words; ++k) {
                            uint64_t const addr =
                                static_cast<uint64_t>(frame.x86->Esp) + 4 + static_cast<uint64_t>(k) * 4;
                            uint32_t v = 0;
                            if (thread->QueryMemoryBuffer(TTD::GuestAddress{ addr },
                                                          TTD::BufferView{ &v, sizeof(v) })
                                    .Memory.Size == sizeof(v)) {
                                rec.args.push_back(captureCallArg(thread, v));
                            }
                        }
                    } else {
                        rec.args.push_back(captureCallArg(thread, ctx->Rcx));
                        rec.args.push_back(captureCallArg(thread, ctx->Rdx));
                        rec.args.push_back(captureCallArg(thread, ctx->R8));
                        rec.args.push_back(captureCallArg(thread, ctx->R9));

                        if (config.with_stack_args) {  // stack slots past the register arguments
                            for (int k = 0; k < 4; ++k) {
                                uint64_t const slot = ctx->Rsp + 0x28 + static_cast<uint64_t>(k) * 8;
                                uint64_t v = 0;
                                if (thread->QueryMemoryBuffer(TTD::GuestAddress{ slot },
                                                              TTD::BufferView{ &v, sizeof(v) })
                                        .Memory.Size == sizeof(v)) {
                                    rec.args.push_back(captureCallArg(thread, v));
                                }
                            }
                        }
                    }
                }

                size_t const idx = out.process.calls.size();
                in_flight[utid].push_back(InFlight{ static_cast<uint64_t>(fall_through), idx,
                                                   frame.arch, std::move(pending),
                                                   std::move(unread_strings) });
                out.process.calls.push_back(std::move(rec));
            } else {
                // Log the most recent call on this thread as returned, capturing its return value.
                auto it = in_flight.find(utid);
                if (it != in_flight.end() && !it->second.empty()) {
                    InFlight& top = it->second.back();
                    if (top.ret_addr == static_cast<uint64_t>(target)) {
                        CallRecord& call = out.process.calls[top.call_index];
                        call.ret = thread->GetBasicReturnValue();
                        call.has_ret = true;
                        // We are standing at the return, which is where the out-param
                        // pass below reads from. Write down where that is: a consumer
                        // then has the call's whole interval and can tell a nested
                        // call from a neighbouring one exactly, rather than guessing
                        // from a step threshold and silently dropping real events on
                        // a busy thread.
                        call.return_position = formatPosition(thread->GetPosition());
                        // Free of charge: we are already here, on the right thread,
                        // with a view that has since watched the callee read the string.
                        bool strings_gained = false;
                        for (uint16_t pi : top.unread_strings) {
                            if (pi < call.params.size()
                                && recoverString(thread, decode_opt, call.params[pi],
                                                 /*accept_truncated=*/false)) {
                                // Deliberately not marked from_return, although this read
                                // happens at the return. That flag exists so a consumer can
                                // tell a pre-call value from a post-call one, and every
                                // parameter reaching here is [In]: the callee does not write
                                // it, so the bytes are the caller's input and describe the
                                // moment of the call. Reading them later is how we recovered
                                // the value, not when it became true. Marking them would put
                                // an '@ret' on every recovered string argument in the
                                // timeline and read as "this was an output".
                                strings_gained = true;
                                ++strings_at_return;
                            }
                        }
                        if (strings_gained && top.pending.empty()) {
                            call.args = toCapaArgs(call.params);
                        }
                        if (!top.pending.empty()) {
                            // The payoff of a time-travel trace: [Out] parameters can be
                            // rendered filled in, which a live debugger can't easily do.
                            // Pointer width has to match the entry pass, so carry the
                            // architecture over rather than re-deriving it here.
                            CallFrame ret_frame;
                            ret_frame.arch = top.arch;
                            ret_frame.thread = thread;
                            resolvePendingOuts(top.pending, ret_frame, decode_opt, call.params);
                            call.args = toCapaArgs(call.params);
                        }
                        it->second.pop_back();
                    }
                }
            }
        };

        sweep->SetCallReturnCallback(on_call_return);
        // Without ReplayAllSegmentsWithoutFiltering the engine only replays segments it
        // thinks can hit an event, and a call/return callback alone doesn't qualify --
        // the sweep then completes instantly having seen nothing.
        sweep->SetReplayFlags(TTD::Replay::ReplayFlags::ReplaySegmentsSequentially |
                              TTD::Replay::ReplayFlags::ReplayAllSegmentsWithoutFiltering);
        sweep->SetPosition(TTD::Replay::Position::Min);
        log::dbg() << "[+] Beginning execution sweep...\n";
        sweep->ReplayForward();

        if (cancelled) {
            log::err() << "[!] Sweep cancelled after " << out.process.calls.size() << " call(s)\n";
            return Status::Cancelled;
        }
        if (limit_hit) {
            log::err() << "[!] Reached the call limit (" << config.max_calls << ")\n";
        }
        log::err() << "[+] Recorded " << out.process.calls.size() << " API calls from "
                   << events_seen << " call/return events\n";
        if (strings_at_return != 0) {
            // The larger half of the string recovery, and free: read at each call's return,
            // inside the sweep, with no seek to pay for. Worth its own line -- the seeking
            // pass below reports only its own remainder, and a log showing that number alone
            // credits the mechanism with a fraction of what it actually recovers.
            log::err() << "[+] Recovered " << strings_at_return
                       << " string argument(s) at their call's return\n";
        }

        auto const recover_start = std::chrono::steady_clock::now();
        Recovery const recovery =
            config.recover_strings
                ? recoverMissedStrings(engine, decode_opt, out, config.cancelled)
                : Recovery{};
        if (recovery.recovered != 0) {
            auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - recover_start)
                                .count();
            log::err() << "[+] Recovered " << recovery.recovered
                       << " string argument(s) the sweep's thread view could not read ("
                       << ms << " ms)\n";
        }
        if (recovery.cancelled) {
            // Cancelled is cancelled, whichever pass was running: ttdcapa.h promises a
            // cancelled pass returns TTDCAPA_E_CANCELLED and produces no output, and the
            // sweep above already behaves that way. Returning Ok here instead would hand the
            // host a report it stopped asking for and call it complete, with some strings
            // silently missing and nothing to tell them from strings the trace never
            // recorded. What was recovered before the stop is still in `out`, as documented.
            log::err() << "[!] String recovery cancelled after " << recovery.recovered
                       << " string(s)\n";
            return Status::Cancelled;
        }
        return Status::Ok;
    }
}  // namespace ttdcapa
