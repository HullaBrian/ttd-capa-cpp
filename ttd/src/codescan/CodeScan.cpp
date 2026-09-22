#include "CodeScan.hpp"

#include "TraceSession.hpp"
#include "DiscoveryPass.hpp"
#include "RegionProviders.hpp"
#include "Region.hpp"
#include "WriteLog.hpp"
#include "ShadowReconstructor.hpp"
#include "Utils.hpp"

#include "../log.hpp"
#include "../ttd_pe_utils.hpp"

#include <algorithm>
#include <exception>
#include <filesystem>
#include <new>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

#include <windows.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

#include <nlohmann/json.hpp>

namespace codescan {
    namespace {
        // One point in the trace where code in the region executed after fresh writes landed. The
        // write count is how many writes had accumulated by then, so the region's contents as of
        // that generation are exactly "apply the first writeCount writes to the shadow buffer".
        // entryAddr is the RIP that ran first -- the natural entry point for disassembly.
        struct Generation {
            size_t writeCount = 0;
            TTD::Replay::Position executePos;
            uint64_t entryAddr = 0;
        };

        struct RegionRecording {
            analysis::WriteLog writes;
            std::vector<Generation> generations;
            // Every distinct instruction address executed in the region, and the subset that began
            // a generation. capa's shellcode analysis disassembles blindly from offset 0 and misses
            // code at arbitrary offsets; feeding it these addresses as code / function entries is
            // what lets it actually see the unpacked routines.
            std::unordered_set<uint64_t> executed;
            std::unordered_set<uint64_t> entries;
            // Whether writes have landed since the last execution was recorded, which is what
            // makes the next execution a generation boundary.
            bool dirtySinceExecute = false;
            // Set when the write log had to be released to stay inside the budget. What was
            // recorded up to then is a partial history, so the region has to be skipped rather
            // than reconstructed from it.
            bool overBudget = false;
            // Set when the engine would not take a watchpoint for this region, so nothing was
            // ever observed for it. Distinct from overBudget only in what it reports.
            bool watchpointFailed = false;

            // Host memory this recording holds, write log included.
            //
            // The write log used to be the whole of it, and for a packer decrypting itself a
            // byte at a time it still usually is. But `executed` grows by one entry per
            // distinct instruction address in the region, and with module images watched by
            // default (see scanSampleModules) a region can be a whole executable that the
            // program runs for the length of the trace -- millions of addresses, none of them
            // counted by a budget that looked only at writes, and none of them released when
            // that budget dropped a region. `entries` and `generations` are smaller but grow
            // for the same reason and are free to add here.
            //
            // The set terms are estimates: a node-based container's real cost is per-node
            // allocator overhead plus a bucket array, and neither is observable. The budget is
            // documented as approximate for the same reason the write log's is.
            uint64_t footprint() const {
                // one 8-byte value plus two list pointers plus allocator header, per node
                constexpr uint64_t kNodeBytes = 40;
                constexpr uint64_t kBucketBytes = sizeof(void*) * 2;
                return this->writes.footprint()
                     + static_cast<uint64_t>(this->executed.size()) * kNodeBytes
                     + static_cast<uint64_t>(this->executed.bucket_count()) * kBucketBytes
                     + static_cast<uint64_t>(this->entries.size()) * kNodeBytes
                     + static_cast<uint64_t>(this->entries.bucket_count()) * kBucketBytes
                     + static_cast<uint64_t>(this->generations.capacity()) * sizeof(Generation);
            }

            // Everything the budget counts, released together. Dropping the write log alone
            // recovers nothing from a region whose cost is its instruction set.
            void release() {
                this->writes = analysis::WriteLog{};
                this->generations.clear();
                this->generations.shrink_to_fit();
                this->executed.clear();
                this->executed.rehash(0);
                this->entries.clear();
                this->entries.rehash(0);
            }
        };

        // One region being recorded by the shared pass, with the recording it is filling.
        struct ScanTarget {
            discovery::Region region;
            bool executable = false;
            RegionRecording recording;
        };

        bool isExecuteAccess(TTD::Replay::DataAccessType type) {
            return type == TTD::Replay::DataAccessType::Execute || type == TTD::Replay::DataAccessType::CodeFetch;
        }

        // Records every target region in ONE replay over the trace: the cursor carries a watchpoint
        // per region rather than a cursor per region carrying one.
        //
        // The engine seeks between watchpoint hits using the index, so watching N ranges costs
        // little more than watching the widest of them -- whereas replaying once per region pays
        // the whole seek-and-decode pipeline N times over. That difference is the single largest
        // cost in this pass: on a 72 MB recording with 65 tracked regions the per-region form
        // spent ~12.5 s in replay where this form spends ~0.6 s, and it is why nothing else here
        // is worth tuning first.
        //
        // What each hit does is unchanged: every write is logged (with its post-write bytes, taken
        // from the writing thread's ThreadLocal view where they are real rather than zero-filled),
        // and every execution is collapsed into a "generation" marker -- but only the first
        // execution following a burst of writes, so a hot loop does not produce a marker per
        // instruction. That gate is what keeps the number of capa scans tiny: one snapshot per
        // (writes -> execute) cycle, which is exactly "the code as it first ran" for a one-shot
        // unpacker and one per stage for a multi-stage loader.
        void recordRegions(ttd::TraceSession& session, std::vector<ScanTarget>& targets,
                           uint64_t writeLogBudget,
                           std::function<bool()> const& isCancelled, bool& cancelled) {
            if (targets.empty()) return;

            // Watchpoint hits are frequent enough that asking the host on every one would be
            // measurable; a check every few thousand keeps cancellation responsive for free.
            constexpr uint64_t kCancelPollInterval = 4096;
            uint64_t accesses = 0;
            // Checking footprints on every access would mean summing every region's containers
            // per byte written; the budget only needs to be enforced to within a few thousand.
            constexpr uint64_t kBudgetPollInterval = 65536;
            uint64_t writes = 0;
            std::vector<uint8_t> scratch;  // reused per write, so it grows to the largest one only

            // Index of the first target whose end is past `address`. Targets are sorted by base and
            // never overlap (MemoryRegions::addRegion rejects overlaps), so they are sorted by end
            // as well and this one search serves both lookups below.
            auto firstTargetPast = [&targets](uint64_t address) -> size_t {
                size_t low = 0, high = targets.size();
                while (low < high) {
                    size_t const mid = low + (high - low) / 2;
                    if (targets[mid].region.end() <= address) low = mid + 1;
                    else high = mid;
                }
                return low;
            };

            // Batching means every live write log is resident at once, so the budget has to be read
            // as a ceiling on their sum rather than on any one of them. Releasing the largest is
            // what actually recovers memory, and the pass keeps going for every other region --
            // stopping the replay here would cost all of them for one region's excess.
            auto enforceBudget = [&]() {
                if (writeLogBudget == 0) return;
                for (;;) {
                    uint64_t total = 0, largestBytes = 0;
                    size_t largest = targets.size();
                    for (size_t i = 0; i < targets.size(); ++i) {
                        if (targets[i].recording.overBudget) continue;
                        uint64_t const footprint = targets[i].recording.footprint();
                        total += footprint;
                        if (footprint > largestBytes) {
                            largestBytes = footprint;
                            largest = i;
                        }
                    }
                    if (total <= writeLogBudget || largest == targets.size()) return;

                    ScanTarget& target = targets[largest];
                    target.recording.overBudget = true;
                    target.recording.release();  // all of it, now; that is the point
                    ttdcapa::log::err() << std::format(
                        "[!] Region 0x{:x} held the largest recording ({} bytes) when the 0x{:x}-byte "
                        "budget was reached; dropping it (raise the write-log budget to "
                        "reconstruct it)\n",
                        target.region.base, largestBytes, writeLogBudget
                    );
                }
            };

            auto onAccess = [&](TTD::Replay::ICursorView::MemoryWatchpointResult const& watchpoint,
                                TTD::Replay::IThreadView const* thread) -> bool {
                if (isCancelled && (++accesses % kCancelPollInterval) == 0 && isCancelled()) {
                    cancelled = true;
                    return true;  // stop the replay
                }
                if (watchpoint.AccessType == TTD::Replay::DataAccessType::Write) {
                    uint64_t const writeLow = static_cast<uint64_t>(watchpoint.Address);
                    uint64_t const writeHigh = writeLow + watchpoint.Size;

                    // Normally one region, but a single write can straddle two adjacent ones.
                    for (size_t i = firstTargetPast(writeLow);
                         i < targets.size() && targets[i].region.base < writeHigh; ++i) {
                        ScanTarget& target = targets[i];
                        if (target.recording.overBudget) continue;

                        uint64_t const low = (std::max)(writeLow, target.region.base);
                        uint64_t const high = (std::min)(writeHigh, target.region.end());
                        if (low >= high) continue;

                        scratch.resize(static_cast<size_t>(high - low));
                        TTD::Replay::MemoryBuffer buffer = thread->QueryMemoryBuffer(
                            TTD::GuestAddress{ low },
                            TTD::BufferView{ scratch.data(), scratch.size() }
                        );
                        if (buffer.Memory.Size == 0) continue;  // nothing recorded here

                        target.recording.writes.push(low, thread->GetPosition(), scratch.data(), buffer.Memory.Size);
                        target.recording.dirtySinceExecute = true;
                    }

                    if ((++writes % kBudgetPollInterval) == 0) enforceBudget();
                } else if (isExecuteAccess(watchpoint.AccessType)) {
                    uint64_t const rip = static_cast<uint64_t>(watchpoint.Address);
                    size_t const i = firstTargetPast(rip);
                    if (i >= targets.size() || targets[i].region.base > rip) return false;

                    RegionRecording& recording = targets[i].recording;
                    if (recording.overBudget) return false;

                    recording.executed.insert(rip);
                    // Polled here as well as on writes. `executed` is now part of the budget,
                    // and a region that runs a great deal of code without being written to --
                    // a watched module image, which is the common case since module scanning
                    // became the default -- would otherwise grow it without ever reaching a
                    // check, because the write counter never advances.
                    if ((++writes % kBudgetPollInterval) == 0) enforceBudget();

                    // The moment information is about to be *used*: snapshot the code that ran, but
                    // only if it changed since the last execution we recorded.
                    if (recording.dirtySinceExecute) {
                        recording.generations.push_back({ recording.writes.size(), thread->GetPosition(), rip });
                        recording.entries.insert(rip);
                        recording.dirtySinceExecute = false;
                    }
                }
                return false;  // observe only: never stop the replay
            };

            TTD::Replay::UniqueCursor cursor = session.NewCursor();
            for (ScanTarget& target : targets) {
                bool const added = cursor->AddMemoryWatchpoint(TTD::Replay::MemoryWatchpointData{
                    .Address = TTD::GuestAddress{ target.region.base },
                    .Size = target.region.size,
                    .AccessMask = TTD::Replay::DataAccessMask::Write | TTD::Replay::DataAccessMask::Execute,
                });
                // One cursor now carries a watchpoint per region rather than one in total, so a
                // refusal here (a capacity limit, a range the engine rejects) is worth saying
                // out loud: the region would otherwise record nothing and be reported as
                // "0 write(s), 0 snapshot(s)", which is exactly how a region that genuinely was
                // never touched reads. A silently unscanned payload region is the worst answer
                // this pass can give.
                if (!added) {
                    target.recording.watchpointFailed = true;
                    ttdcapa::log::err() << std::format(
                        "[-] The engine refused a watchpoint on region 0x{:x} (0x{:x} bytes); it "
                        "cannot be recorded and is skipped\n",
                        target.region.base, target.region.size
                    );
                }
            }
            cursor->SetMemoryWatchpointCallback(onAccess);
            cursor->SetEventMask(TTD::Replay::EventMask::MemoryWatchpoint);
            // Watchpoints are the cursor's only events, so the engine can skip whole segments that
            // touch none of the regions -- which is where the saving over N passes comes from.
            // Sequential ordering is required: reconstruction is "last write wins", and that is
            // only the state as of a position if the writes arrive in the order they happened.
            cursor->SetReplayFlags(TTD::Replay::ReplayFlags::ReplaySegmentsSequentially);
            cursor->SetPosition(TTD::Replay::Position::Min);
            cursor->ReplayForward();

            enforceBudget();
        }

        // Applies writes [from, to) to the shadow. Returns whether any of them changed a byte.
        bool applyWrites(analysis::ShadowReconstructor& shadow, analysis::WriteLog const& writes,
                         size_t from, size_t to) {
            bool changed = false;
            for (size_t i = from; i < to; ++i) {
                analysis::WriteView const write = writes[i];
                analysis::ShadowReconstructor::Clip clip;
                if (shadow.clip(write, clip) && shadow.apply(write, clip)) changed = true;
            }
            return changed;
        }

        // Decides which generations are worth dumping -- without materializing a single one.
        //
        // A region under a byte-at-a-time decryptor executes between almost every write, so
        // "generations" runs to tens of thousands. Building an image per generation and only then
        // keeping `maxScans` of them multiplies the region's size by that count: a few megabytes
        // of shellcode becomes hundreds of gigabytes of host memory, which is exactly how this
        // used to die. Selection here reads the write log alone -- a generation is a candidate
        // when some write since the last candidate actually changed a byte, which is the same
        // "not identical to the one we kept" test the old code paid a full-region compare for.
        // (A state that changes and then changes back is no longer recognised as a duplicate;
        // that costs at most one redundant snapshot and saves a compare per generation.)
        // The region's memory as of `position`, page by page.
        //
        // This is what a region's contents were before anything we watched touched them, and
        // for anything the loader mapped it is most of the answer: a module reconstructed
        // from writes alone has no PE header, no import directory and no section table,
        // because none of that arrived as a write inside the trace. An unpacker's output
        // then reads as a headerless blob rather than as the image it is.
        //
        // One query stops at the first byte the trace cannot answer for, and regions have
        // holes -- pages never touched, pages the recording never saw. Walking a page at a
        // time keeps a hole costing one page instead of everything past it. What no query
        // can supply stays zero, which is what the whole buffer used to be.
        std::vector<uint8_t> readRegionMemory(ttd::TraceSession& session,
                                              TTD::Replay::Position const& position,
                                              discovery::Region const& region) {
            constexpr uint64_t kPage = 0x1000;

            std::vector<uint8_t> out;
            try {
                out.assign(static_cast<size_t>(region.size), 0);
            } catch (std::bad_alloc const&) {
                return {};  // the write log alone, exactly as before
            }

            TTD::Replay::UniqueCursor cursor = session.NewCursor(position);
            uint64_t recovered = 0;
            for (uint64_t offset = 0; offset < region.size; offset += kPage) {
                uint64_t const want = (std::min)(kPage, region.size - offset);
                TTD::Replay::MemoryBuffer buffer = cursor->QueryMemoryBuffer(
                    TTD::GuestAddress{ region.base + offset },
                    TTD::BufferView{ out.data() + offset, static_cast<size_t>(want) }
                );
                recovered += buffer.Memory.Size;
            }

            if (recovered == 0) return {};
            ttdcapa::log::dbg() << std::format(
                "    [+] Seeded region 0x{:x} with 0x{:x} of 0x{:x} byte(s) from the trace\n",
                region.base, recovered, region.size
            );
            return out;
        }

        std::vector<Generation> selectGenerations(discovery::Region const& region,
                                                  RegionRecording const& recording, size_t maxScans,
                                                  std::vector<uint8_t> const& initial) {
            std::vector<Generation> selected;
            if (recording.writes.empty()) return selected;

            // Normally each generation is "code executed after fresh writes". When no execution was
            // observed in the region at all -- always the case for data regions under --scan-data,
            // and a rare edge for code the execute watchpoint never caught -- fall back to the
            // region's final written state so it still gets scanned instead of silently dropped.
            std::vector<Generation> generations = recording.generations;
            if (generations.empty()) {
                generations.push_back({ recording.writes.size(), recording.writes.lastPosition() });
            }

            analysis::ShadowReconstructor shadow(region.base, region.size);
            shadow.seed(initial);
            size_t applied = 0;
            bool changedSinceKept = false;

            for (Generation const& generation : generations) {
                size_t const target = (std::min)(generation.writeCount, recording.writes.size());
                if (applyWrites(shadow, recording.writes, applied, target)) changedSinceKept = true;
                applied = (std::max)(applied, target);

                if (!shadow.hasNonZero()) continue;  // an all-zero state has nothing to disassemble
                // Two generations can reconstruct to the same bytes (e.g. re-execution after a
                // no-op write); scanning the same content twice just wastes a capa run.
                if (!selected.empty() && !changedSinceKept) continue;

                selected.push_back(generation);
                changedSinceKept = false;
            }

            if (maxScans > 0 && selected.size() > maxScans) {
                ttdcapa::log::err() << std::format(
                    "    [!] Region 0x{:x} produced {} snapshots; keeping {} evenly spread "
                    "(raise the per-region scan limit to keep more)\n",
                    region.base, selected.size(), maxScans
                );
                // Spread the kept snapshots across the whole timeline, always including the first
                // (freshest code) and the last (most-decrypted state). Keeping only the first N
                // would miss the fully-unpacked end of a decrypt-and-execute-in-place region.
                std::vector<Generation> kept;
                kept.reserve(maxScans);
                size_t const last = selected.size() - 1;
                for (size_t i = 0; i < maxScans; ++i) {
                    size_t const idx = (maxScans == 1) ? last : (i * last) / (maxScans - 1);
                    kept.push_back(selected[idx]);
                }
                selected = std::move(kept);
            }

            return selected;
        }

        // Second pass over the write log: reconstruct each selected generation in turn and hand it
        // to `emit` before moving on, so only one region image is ever in memory. `selected` is in
        // write-log order, which is what makes a single forward pass enough.
        template <typename Emit>
        void emitSnapshots(discovery::Region const& region, RegionRecording const& recording,
                           std::vector<Generation> const& selected,
                           std::vector<uint8_t> const& initial, Emit&& emit) {
            if (selected.empty()) return;

            analysis::ShadowReconstructor shadow(region.base, region.size);
            shadow.seed(initial);
            size_t applied = 0;

            for (Generation const& generation : selected) {
                size_t const target = (std::min)(generation.writeCount, recording.writes.size());
                applyWrites(shadow, recording.writes, applied, target);
                applied = (std::max)(applied, target);
                emit(generation, shadow.data(), shadow.size());
            }
        }

        // The architecture of the recorded process's own image. The manifest names it so the
        // static scan disassembles the reconstructed regions in the right mode: handing 32-bit
        // shellcode to an x64 decoder produces plausible-looking nonsense rather than an error.
        // SystemInfo cannot answer this -- it reports the recording machine, and a WoW64 guest
        // is recorded on an x64 one -- so it comes from the main module's headers.
        char const* traceArch(ttd::TraceSession& session) {
            TTD::Replay::IReplayEngine* engine = session.getEngine();
            size_t const count = engine->GetModuleCount();
            TTD::Replay::Module const* modules = engine->GetModuleList();

            TTD::Replay::UniqueCursor cursor = session.NewCursor();
            cursor->SetPosition(engine->GetFirstPosition());

            for (size_t i = 0; i < count; ++i) {
                std::wstring name = modules[i].pName != nullptr ? modules[i].pName : L"";
                if (name.size() < 4) continue;
                std::wstring ext = name.substr(name.size() - 4);
                for (wchar_t& c : ext) c = static_cast<wchar_t>(towlower(c));
                if (ext != L".exe") continue;

                ttdcapa::ModuleFormat format;
                if (ttdcapa::getModuleFormat(&cursor, modules[i].Address, format)) {
                    return ttdcapa::archName(format);
                }
                break;
            }
            // Unreadable headers, or a trace with no .exe in the module list. x64 is the safer
            // default: it is what the great majority of traces are, and the manifest's consumer
            // treats this as a disassembly hint rather than a hard fact.
            return "x64";
        }

        // Is this module one the sample brought, rather than one Windows did?
        //
        // Path-based, and deliberately coarse: everything under the Windows directory
        // covers System32, SysWOW64 and WinSxS in one test, and a module loaded from
        // anywhere else is the sample, something it dropped, or something it injected --
        // all of which are worth reconstructing.
        bool isSampleModule(std::wstring const& path) {
            if (path.empty()) return false;
            std::wstring lower = path;
            for (wchar_t& c : lower) c = static_cast<wchar_t>(towlower(c));
            return lower.find(L"\\windows\\") == std::wstring::npos;
        }

        // The sample's own module images, as regions to record. See Config::scanSampleModules.
        //
        // Ranges only; whether anything was ever written into them is what the recording
        // pass decides, and a module that is never written produces no generation and so
        // no snapshot. That is the whole filter: an ordinary DLL costs a watchpoint and
        // nothing else, while a packed image reconstructs to its unpacked self.
        std::vector<discovery::Region> sampleModuleRegions(ttd::TraceSession& session,
                                                           discovery::MemoryRegions const& existing) {
            TTD::Replay::IReplayEngine* engine = session.getEngine();
            size_t const count = engine->GetModuleCount();
            TTD::Replay::Module const* modules = engine->GetModuleList();

            std::vector<discovery::Region> out;
            for (size_t i = 0; i < count; ++i) {
                std::wstring const path = modules[i].pName != nullptr ? modules[i].pName : L"";
                if (!isSampleModule(path)) continue;

                uint64_t const base = static_cast<uint64_t>(modules[i].Address);
                uint64_t const size = modules[i].Size;
                if (base == 0 || size == 0) continue;
                // A discovered allocation already covering this is the better record of it:
                // it is what the process actually did, and MemoryRegions rejects overlaps
                // anyway.
                if (existing.overlapsExisting(base, size)) continue;

                discovery::Region region;
                region.base = base;
                region.size = size;
                // An image is executable by definition; saying so here is what puts it on
                // the exec-only scan path rather than behind --scan-data.
                region.protection = discovery::ExecuteReadProtection;
                out.push_back(region);

                ttdcapa::log::dbg() << std::format(
                    "    [+] Watching sample module {} @ {:#x} ({:#x} bytes)\n",
                    wideToUTF8(std::wstring(TTD::Replay::GetModuleBaseName(modules[i].pName,
                                                                          modules[i].NameLength))),
                    base, size
                );
            }
            return out;
        }

        // Every module the trace loaded, with its named exports.
        //
        // This is the piece the region dumps can never supply. Shellcode that resolved its
        // imports with GetProcAddress stores bare addresses in a table of its own -- a beacon
        // typically has a couple of hundred of them -- and the target of every one of them is
        // OUTSIDE every region scanned. Only an export map spanning the whole process can say
        // that 0x7ffa6a09bf20 is kernel32!VirtualAlloc, and that is what turns an anonymous
        // `call [rbx+0x28]` into an `api:` feature on the consumer side.
        //
        // Exports are recorded as RVAs: the module's own `base` is right beside them, and a
        // busy trace yields tens of thousands of entries, where the absolute form would spend
        // fifteen digits per line saying the same thing.
        nlohmann::json collectModules(ttd::TraceSession& session) {
            TTD::Replay::IReplayEngine* engine = session.getEngine();
            size_t const count = engine->GetModuleLoadedEventCount();
            TTD::Replay::ModuleLoadedEvent const* events = engine->GetModuleLoadedEventList();

            TTD::Replay::UniqueCursor cursor = session.NewCursor();

            nlohmann::json out = nlohmann::json::array();
            size_t totalExports = 0;
            // A module can be loaded, unloaded and loaded again at the same base, and each
            // load is its own event. The export map is keyed by address, so a second copy
            // would only add duplicate entries for addresses already covered.
            std::unordered_set<uint64_t> seenBases;

            for (size_t i = 0; i < count; ++i) {
                TTD::Replay::Module const* loadedModule = events[i].pModule;
                if (loadedModule == nullptr) continue;
                uint64_t const base = static_cast<uint64_t>(loadedModule->Address);
                if (!seenBases.insert(base).second) continue;

                // Read the image at the position it loaded at. The end of the trace would be
                // wrong for anything unloaded before then -- its pages are gone by then, and
                // whatever occupies them now is not this module.
                cursor->SetPosition(events[i].Position);

                std::wstring const full = loadedModule->pName != nullptr ? loadedModule->pName : L"";

                nlohmann::json entry;
                entry["name"] = wideToUTF8(std::wstring(
                    TTD::Replay::GetModuleBaseName(loadedModule->pName, loadedModule->NameLength)));
                entry["path"] = wideToUTF8(full);
                entry["base"] = base;
                entry["size"] = static_cast<uint64_t>(loadedModule->Size);

                ttdcapa::ModuleFormat format;
                if (ttdcapa::getModuleFormat(&cursor, loadedModule->Address, format)) {
                    entry["arch"] = ttdcapa::archName(format);
                }

                std::vector<std::pair<uint64_t, std::string>> exports;
                ttdcapa::getModuleExports(&cursor, loadedModule->Address, exports);

                nlohmann::json exportArray = nlohmann::json::array();
                for (auto const& [va, name] : exports) {
                    // getModuleExports reports absolute addresses. One outside the module's
                    // own extent is a header we misread, not an export.
                    if (va < base || va - base >= loadedModule->Size) continue;
                    exportArray.push_back(nlohmann::json::array({ va - base, name }));
                }
                totalExports += exportArray.size();
                entry["exports"] = std::move(exportArray);

                out.push_back(std::move(entry));
            }

            ttdcapa::log::dbg() << std::format(
                "[+] Recorded {} module(s) and {} export(s) for symbol resolution\n",
                out.size(), totalExports
            );
            return out;
        }

        std::string dumpFileName(discovery::Region const& region, TTD::Replay::Position const& position) {
            return std::format(
                "code_{:x}_{:x}_{:x}.bin",
                static_cast<uint64_t>(position.Sequence),
                static_cast<uint64_t>(position.Steps),
                region.base
            );
        }
    }  // namespace

    ttdcapa::Status run(Config const& config, std::string* manifestJson) {
        if (config.trace.empty()) return ttdcapa::Status::InvalidArgument;

        // TraceSession reports engine and trace-open failures by throwing. Catching them here
        // keeps the pass's contract "returns a status" for every caller, which matters most
        // for the C API, where an exception crossing the DLL boundary is undefined behaviour.
        std::optional<ttd::TraceSession> sessionStorage;
        try {
            sessionStorage.emplace(config.trace, config.rebuildIndex);
        } catch (std::exception const& e) {
            ttdcapa::log::err() << e.what() << "\n";
            return ttdcapa::Status::EngineFailed;
        }
        ttd::TraceSession& session = *sessionStorage;

        // The providers below read syscall arguments, which means a calling convention, and x86
        // and x64 are the two this knows. Everything after region discovery -- the write
        // watchpoints, the reconstruction -- is architecture-neutral, but discovery feeds it, so
        // the check belongs here rather than deeper in.
        char const* const arch = traceArch(session);
        if (std::string_view(arch) != "x86" && std::string_view(arch) != "x64") {
            ttdcapa::log::err() << std::format("[-] Unsupported trace architecture: {}\n", arch);
            return ttdcapa::Status::UnsupportedArch;
        }

        // Providers finalize in registration order, and the protection classifier only reclassifies
        // what the other two found, so it goes last.
        ttdcapa::log::dbg() << "[+] Building region filters...\n";
        discovery::DiscoveryPass discoveryPass;
        discoveryPass.addProvider<discovery::NtAllocateVirtualMemoryProvider>(session);
        discoveryPass.addProvider<discovery::NtMapViewOfSectionProvider>(session);
        discoveryPass.addProvider<discovery::NtProtectVirtualMemoryProvider>(session);

        discovery::MemoryRegions regions = discoveryPass.run(session);

        if (config.scanSampleModules) {
            ttdcapa::log::dbg() << "[+] Adding the sample's own module images...\n";
            size_t added = 0;
            for (discovery::Region const& region : sampleModuleRegions(session, regions))
                if (regions.addRegion(region)) ++added;
            ttdcapa::log::dbg() << std::format("[+] Tracking {} sample module image(s)\n", added);
        }

        std::error_code ec;
        if (!config.dumpDir.empty()) {
            std::filesystem::create_directories(config.dumpDir, ec);
        }

        nlohmann::json manifest;
        manifest["version"] = 1;
        manifest["trace"] = wideToUTF8(config.trace);
        manifest["arch"] = arch;
        manifest["modules"] = collectModules(session);
        manifest["regions"] = nlohmann::json::array();

        size_t regionsScanned = 0;
        size_t totalSnapshots = 0;

        bool cancelled = false;

        // Everything the shared recording pass will watch, in base order (which is how
        // MemoryRegions iterates, and what recordRegions' binary search relies on).
        std::vector<ScanTarget> targets;
        for (auto const& [base, region] : regions) {
            if (config.cancelled && config.cancelled()) {
                cancelled = true;
                break;
            }
            bool const executable = region.isExecutable();
            if (!executable && !config.includeData) continue;  // assembly scanning is exec-only by default
            if (region.size == 0) continue;

            // A region big enough to be worth this much host memory is not shellcode; it is a
            // mapping the discovery pass had no reason to reject. Reconstructing it would cost a
            // buffer of its full size in each of the two passes below, so say what was skipped
            // rather than trying and dying.
            if (config.maxRegionBytes != 0 && region.size > config.maxRegionBytes) {
                ttdcapa::log::err() << std::format(
                    "[!] Region 0x{:x} (0x{:x} bytes) is larger than the 0x{:x}-byte region budget; "
                    "skipping it (raise the region budget to include it)\n",
                    region.base, region.size, config.maxRegionBytes
                );
                continue;
            }

            targets.push_back(ScanTarget{ region, executable });
        }

        if (!cancelled && !targets.empty()) {
            ttdcapa::log::dbg() << std::format(
                "[+] Recording {} region(s) in one replay...\n", targets.size()
            );
            // Replay 2 of 2. This is the stage that used to scale with the region count; if it
            // ever does again, a per-region replay has crept back in.
            //
            // One replay covers every region, so unlike the per-region form there is no way to
            // lose just the region that ran out of memory: the pass stops wherever it stopped and
            // every log is partial from that point, with no way to tell which. Emitting them
            // would report regions as scanned on a truncated history, so the scan ends here --
            // but it ends as a status with the knobs that would prevent it, which is this
            // function's contract to the C API, rather than as an exception through the caller.
            try {
                ttd::StageTimer timer("Region recording replay");
                recordRegions(session, targets, config.maxWriteLogBytes, config.cancelled, cancelled);
            } catch (std::bad_alloc const&) {
                try {
                    ttdcapa::log::err()
                        << "[-] Ran out of memory recording the tracked regions; no manifest written. "
                           "Lower the write-log budget (it bounds every region's write log together) "
                           "or the region budget to rule the largest regions out sooner.\n";
                } catch (...) {
                    // Too little memory left to even say so.
                }
                return ttdcapa::Status::Internal;
            }
        }

        // Reconstructs one recorded region and appends it to the manifest. The replay is over by
        // now, so this only reads the write log the pass above filled.
        auto emitRegion = [&](ScanTarget& target) {
            discovery::Region const& region = target.region;
            RegionRecording& recording = target.recording;
            bool const executable = target.executable;

            // Both mean "this region was never fully observed", and reconstructing from what
            // little there is would misreport it as scanned.
            if (recording.overBudget || recording.watchpointFailed) return;

            // Read at the region's first execution rather than at the start of the trace: a
            // module loaded, or a view mapped, part way through has nothing at its address
            // before then. Every write in the log is at or after that point for the states
            // this reconstructs, and re-applying the ones before it just writes back the
            // bytes the read already holds.
            std::vector<uint8_t> initial;
            if (!recording.generations.empty()) {
                initial = readRegionMemory(session, recording.generations.front().executePos, region);
            }

            std::vector<Generation> const snapshots =
                selectGenerations(region, recording, config.maxScansPerRegion, initial);

            // A per-region summary of work that *succeeded*, so it is tagged as a result, not a
            // warning. As "[!]" it survived every host filter aimed at warnings and printed one
            // line per region on an otherwise quiet run.
            ttdcapa::log::err() << std::format(
                "[+] Region 0x{:x} (0x{:x} bytes, {} write(s), {} snapshot(s)) [{}]\n",
                region.base, region.size, recording.writes.size(), snapshots.size(),
                executable ? "exec" : "data"
            );

            if (snapshots.empty()) return;

            nlohmann::json regionEntry;
            regionEntry["base"] = region.base;
            regionEntry["size"] = region.size;
            regionEntry["classification"] = executable ? "exec" : "data";

            // Sorted, deduped code addresses for the Python side to seed vivisect with: `entries`
            // are generation start RIPs (best function-entry candidates, always kept in full),
            // `executed` is every instruction address seen (so mid-function code still gets
            // disassembled). vivisect's flow-following from `entries` already recovers the great
            // majority of code, so `executed` is a bounded top-up: cap it to keep the manifest
            // small for pathologically hot regions, sampling evenly across the address range.
            constexpr size_t kMaxExecutedSeeds = 131072;
            std::vector<uint64_t> entries(recording.entries.begin(), recording.entries.end());
            std::sort(entries.begin(), entries.end());
            std::vector<uint64_t> executed(recording.executed.begin(), recording.executed.end());
            std::sort(executed.begin(), executed.end());
            if (executed.size() > kMaxExecutedSeeds) {
                std::vector<uint64_t> sampled;
                sampled.reserve(kMaxExecutedSeeds);
                size_t const last = executed.size() - 1;
                for (size_t i = 0; i < kMaxExecutedSeeds; ++i) {
                    sampled.push_back(executed[(i * last) / (kMaxExecutedSeeds - 1)]);
                }
                executed = std::move(sampled);
            }
            regionEntry["entries"] = entries;
            regionEntry["executed"] = executed;
            regionEntry["dumps"] = nlohmann::json::array();

            // Counted locally and folded into the totals only once the region is in the manifest.
            // Everything from here on allocates -- the dumps array, the manifest append -- and if
            // one of those throws, the summary line must not claim snapshots the manifest does not
            // list, because the manifest is what capa-cpp reads.
            size_t written = 0;

            emitSnapshots(region, recording, snapshots, initial,
                          [&](Generation const& snapshot, uint8_t const* bytes, size_t size) {
                std::string const fileName = dumpFileName(region, snapshot.executePos);
                std::filesystem::path const outPath = config.dumpDir.empty()
                    ? std::filesystem::path(fileName)
                    : config.dumpDir / fileName;

                std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
                if (!out) {
                    ttdcapa::log::err() << std::format("    [-] Could not write snapshot {}\n", outPath.string());
                    return;
                }
                out.write(reinterpret_cast<char const*>(bytes), static_cast<std::streamsize>(size));
                out.close();

                regionEntry["dumps"].push_back({
                    { "file", fileName },
                    { "position", ttd::positionToString(snapshot.executePos) },
                    { "entry", snapshot.entryAddr },
                });
                ++written;
            });

            manifest["regions"].push_back(std::move(regionEntry));
            totalSnapshots += written;
            ++regionsScanned;
        };

        // A partially-recorded region would misreport its generations, so a cancel during the
        // recording pass discards the whole thing rather than emitting what it got.
        for (ScanTarget& target : targets) {
            if (cancelled) break;
            if (config.cancelled && config.cancelled()) {
                cancelled = true;
                break;
            }

            // The budgets keep the expected cases in bounds, but a region that gets past them
            // should cost that one region rather than the whole scan.
            try {
                emitRegion(target);
            } catch (std::bad_alloc const&) {
                // Reporting this allocates too -- formatting the address, growing the stream's
                // buffer -- and the one thing this handler must not do is throw its way out of a
                // function whose contract is to return a status. Whatever memory is left decides
                // how much of the message gets out; the region is skipped either way. Snapshots
                // already flushed to disk stay there, unlisted, since no manifest entry was made.
                try {
                    ttdcapa::log::err() << std::format(
                        "[-] Ran out of memory reconstructing region 0x{:x} (0x{:x} bytes); skipping it. "
                        "Lower the region or write-log budget to rule it out sooner.\n",
                        target.region.base, target.region.size
                    );
                } catch (...) {
                    // Too little memory left to even say so. The region is skipped regardless.
                }
            }

            // The write log is the bulk of what a recording holds and nothing reads it after its
            // own region is emitted, so release it as we go rather than at the end of the loop:
            // batching made every log resident at once, and this is what unwinds that.
            target.recording = RegionRecording{};
        }

        if (cancelled) {
            ttdcapa::log::err() << "[!] Code scan cancelled; no manifest written\n";
            return ttdcapa::Status::Cancelled;
        }

        std::string const serialized = manifest.dump(2);
        if (manifestJson != nullptr) *manifestJson = serialized;

        if (!config.manifestPath.empty()) {
            std::ofstream manifestFile(config.manifestPath, std::ios::binary);
            if (!manifestFile) {
                ttdcapa::log::err() << std::format("[-] Could not open manifest for writing: {}\n", config.manifestPath.string());
                return ttdcapa::Status::IoFailed;
            }
            manifestFile << serialized << "\n";
            manifestFile.close();
        }

        ttdcapa::log::err() << std::format(
            "[+] Wrote {} snapshot(s) from {} region(s) to {}; manifest: {}\n",
            totalSnapshots, regionsScanned,
            config.dumpDir.empty() ? std::string(".") : config.dumpDir.string(),
            config.manifestPath.empty() ? std::string("(in memory)") : config.manifestPath.string()
        );
        return ttdcapa::Status::Ok;
    }
}
