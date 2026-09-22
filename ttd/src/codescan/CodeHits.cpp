#include "CodeHits.hpp"

#include "TraceSession.hpp"
#include "Utils.hpp"

#include "../log.hpp"

#include <algorithm>
#include <exception>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <windows.h>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

#include <nlohmann/json.hpp>

namespace codehits {
    namespace {
        bool isExecuteAccess(TTD::Replay::DataAccessType type) {
            return type == TTD::Replay::DataAccessType::Execute ||
                   type == TTD::Replay::DataAccessType::CodeFetch;
        }

        struct VaSet {
            std::vector<uint64_t> vas;
            std::unordered_map<uint64_t, uint64_t> region;  // va -> region base (for reentry mode)
        };

        // Accept either a bare JSON array of VAs, or capa-cpp's `-o` records array (objects
        // that carry a "vas" list and a "base"); collect the union of executable match VAs,
        // and the region base each VA belongs to.
        //
        // A record's "vas" are *container* addresses: capa files a match at its scope's
        // address, so a function-scope rule sits at the entry of the function holding the
        // behaviour. capa-cpp additionally reports, per container, the addresses the rule's
        // own features matched at ("featureVas"), and those are traced alongside. Nothing
        // here treats them differently -- they are simply more addresses to watch -- and a
        // record written before that field existed contributes none, which is the behaviour
        // this pass has always had.
        VaSet parseVas(nlohmann::json const& j) {
            std::unordered_set<uint64_t> uniq;
            std::unordered_map<uint64_t, uint64_t> region;
            if (j.is_array()) {
                for (auto const& e : j) {
                    if (e.is_number()) {
                        uniq.insert(e.get<uint64_t>());
                    } else if (e.is_object() && e.contains("vas") && e["vas"].is_array()) {
                        uint64_t const base = e.value("base", static_cast<uint64_t>(0));
                        for (auto const& v : e["vas"]) {
                            uint64_t const va = v.get<uint64_t>();
                            uniq.insert(va);
                            region.emplace(va, base);  // a VA belongs to one region
                        }
                        auto const featureVas = e.find("featureVas");
                        if (featureVas == e.end() || !featureVas->is_array()) continue;
                        for (auto const& group : *featureVas) {
                            auto const features = group.find("features");
                            if (features == group.end() || !features->is_array()) continue;
                            for (auto const& v : *features) {
                                if (!v.is_number_unsigned()) continue;
                                uint64_t const va = v.get<uint64_t>();
                                uniq.insert(va);
                                region.emplace(va, base);
                            }
                        }
                    }
                }
            }
            VaSet out;
            out.vas.assign(uniq.begin(), uniq.end());
            out.region = std::move(region);
            return out;
        }
    }  // namespace

    ttdcapa::Status run(Config const& config, std::string* hitsJson) {
        if (config.trace.empty()) return ttdcapa::Status::InvalidArgument;

        VaSet vaset;
        try {
            nlohmann::json input;
            if (!config.vasInput.empty()) {
                std::ifstream in(config.vasInput);
                if (!in) {
                    ttdcapa::log::err() << std::format("[-] cannot open VAs input: {}\n", config.vasInput.string());
                    return ttdcapa::Status::InvalidArgument;
                }
                in >> input;
            } else if (!config.vasJson.empty()) {
                input = nlohmann::json::parse(config.vasJson);
            } else {
                return ttdcapa::Status::InvalidArgument;
            }
            vaset = parseVas(input);
        } catch (nlohmann::json::exception const& e) {
            ttdcapa::log::err() << std::format("[-] could not parse the matched-VA records: {}\n", e.what());
            return ttdcapa::Status::BadInput;
        }
        std::vector<uint64_t>& vas = vaset.vas;
        std::sort(vas.begin(), vas.end());

        nlohmann::json arr = nlohmann::json::array();
        // Emitting the (possibly empty) record set is part of every success path: a caller
        // that asked for hits gets a well-formed answer even when nothing was traceable.
        auto emitOutput = [&]() -> ttdcapa::Status {
            std::string const serialized = arr.dump(2);
            if (hitsJson != nullptr) *hitsJson = serialized;
            if (config.output.empty()) return ttdcapa::Status::Ok;

            std::ofstream out(config.output, std::ios::binary);
            if (!out) {
                ttdcapa::log::err() << std::format("[-] cannot write hits output: {}\n", config.output.string());
                return ttdcapa::Status::IoFailed;
            }
            out << serialized << "\n";
            return ttdcapa::Status::Ok;
        };

        if (vas.empty()) {
            ttdcapa::log::err() << "[codehits] no VAs to trace (no insn-scope code capabilities)\n";
            return emitOutput();
        }

        std::optional<ttd::TraceSession> sessionStorage;
        try {
            sessionStorage.emplace(config.trace, config.rebuildIndex);
        } catch (std::exception const& e) {
            ttdcapa::log::err() << e.what() << "\n";
            return ttdcapa::Status::EngineFailed;
        }
        ttd::TraceSession& session = *sessionStorage;

        // No architecture gate: this pass only places execute watchpoints on addresses it was
        // handed and records where they fired, which never touches a register or a calling
        // convention. Gating it on SystemInfo would also be the wrong test -- that field
        // describes the *recording machine*, so a 32-bit guest recorded on an x64 box reports
        // AMD64 either way.

        // Visit-coalescing dedup: a VA accumulates one or more "visits". Consecutive hits
        // whose Sequence gap stays within gapThreshold extend the current visit; a larger gap
        // opens a new one. Replaying forward delivers hits in trace order, so Sequence is
        // non-decreasing across calls for a given VA.
        struct Visit {
            TTD::Replay::Position first{};
            uint64_t tid = 0;
            uint64_t count = 0;
        };
        struct Tracked {
            std::vector<Visit> visits;
            uint64_t lastBurst = 0;  // burst id of the current (last) visit
            bool truncated = false;
        };
        std::unordered_map<uint64_t, Tracked> hits;
        hits.reserve(vas.size());
        for (uint64_t va : vas) hits.emplace(va, Tracked{});

        // The "group" whose execution continuity defines a burst: the VA itself in visit mode,
        // or its region base in reentry mode. A group has a monotonically increasing burst id
        // that ticks whenever the group's execution gaps past the threshold. Every VA in the
        // group opens a fresh visit when the group's burst id advances -- so a shared region
        // burst boundary applies to all its capabilities, not just the first VA that noticed.
        auto groupKey = [&](uint64_t va) -> uint64_t {
            if (!config.reentry) return va;
            auto it = vaset.region.find(va);
            return it != vaset.region.end() ? it->second : 0;
        };
        struct GroupState {
            uint64_t lastSeq = 0;
            uint64_t burst = 0;
            bool seen = false;
        };
        std::unordered_map<uint64_t, GroupState> groupState;

        bool cancelled = false;
        uint64_t accesses = 0;
        constexpr uint64_t kCancelPollInterval = 4096;

        auto onAccess = [&](TTD::Replay::ICursorView::MemoryWatchpointResult const& watchpoint,
                            TTD::Replay::IThreadView const* thread) -> bool {
            if (config.cancelled && (++accesses % kCancelPollInterval) == 0 && config.cancelled()) {
                cancelled = true;
                return true;  // stop the replay
            }
            if (!isExecuteAccess(watchpoint.AccessType)) return false;
            uint64_t const va = static_cast<uint64_t>(watchpoint.Address);
            auto it = hits.find(va);
            if (it == hits.end()) return false;  // an address we aren't tracking
            Tracked& t = it->second;

            TTD::Replay::Position pos = thread->GetPosition();
            uint64_t const seq = static_cast<uint64_t>(pos.Sequence);

            // Advance the group's burst id once per hit (the first VA to cross the gap ticks
            // it; the rest of the burst see the already-ticked id and still open new visits).
            GroupState& g = groupState[groupKey(va)];
            if (g.seen && seq > g.lastSeq && (seq - g.lastSeq) > config.gapThreshold) ++g.burst;
            g.lastSeq = seq;
            g.seen = true;

            bool const newVisit = t.visits.empty() || t.lastBurst != g.burst;
            if (newVisit) {
                if (t.visits.size() < config.maxVisitsPerVa) {
                    t.visits.push_back(Visit{
                        pos, static_cast<uint64_t>(thread->GetThreadInfo().UniqueId), 1});
                } else {
                    // hit the per-VA cap: keep counting into the last visit rather than
                    // spawning unbounded records.
                    ++t.visits.back().count;
                    t.truncated = true;
                }
            } else {
                ++t.visits.back().count;
            }
            t.lastBurst = g.burst;
            return false;  // observe only; never stop the replay
        };

        TTD::Replay::UniqueCursor cursor = session.NewCursor();
        // One execute watchpoint per matched instruction VA. The match set is small (one
        // per capability match location), so the watchpoint count stays modest; the index
        // lets the engine replay only the segments that touch these addresses.
        for (uint64_t va : vas) {
            cursor->AddMemoryWatchpoint(TTD::Replay::MemoryWatchpointData{
                .Address = TTD::GuestAddress{ va },
                .Size = 1,
                .AccessMask = TTD::Replay::DataAccessMask::Execute,
            });
        }
        cursor->SetMemoryWatchpointCallback(onAccess);
        cursor->SetEventMask(TTD::Replay::EventMask::MemoryWatchpoint);
        cursor->SetReplayFlags(TTD::Replay::ReplayFlags::ReplaySegmentsSequentially);
        cursor->SetPosition(TTD::Replay::Position::Min);
        cursor->ReplayForward();

        if (cancelled) {
            ttdcapa::log::err() << "[codehits] cancelled; partial hits discarded\n";
            return ttdcapa::Status::Cancelled;
        }

        size_t executedVas = 0;
        size_t totalVisits = 0;
        bool anyTruncated = false;
        for (uint64_t va : vas) {
            Tracked const& t = hits[va];
            if (t.visits.empty()) continue;  // watched but never executed in the recording
            ++executedVas;
            anyTruncated = anyTruncated || t.truncated;
            for (Visit const& v : t.visits) {
                ++totalVisits;
                arr.push_back({
                    { "va", va },
                    { "position", ttd::positionToString(v.first) },
                    { "tid", v.tid },
                    { "hits", v.count },
                });
            }
        }

        ttdcapa::log::err() << std::format(
            "[codehits] traced {} VA(s); {} executed as {} visit(s) ({} dedup, gap {}).\n",
            vas.size(), executedVas, totalVisits,
            config.reentry ? "reentry" : "visit", config.gapThreshold);
        if (anyTruncated) {
            ttdcapa::log::err() << std::format("[codehits] some VAs hit the {}-visit cap; extra runs folded"
                                     " into the last visit's count.\n", config.maxVisitsPerVa);
        }
        return emitOutput();
    }
}  // namespace codehits
