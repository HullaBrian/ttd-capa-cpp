#ifndef CODESCAN_WRITELOG_HPP
#define CODESCAN_WRITELOG_HPP

#include <cstdint>
#include <vector>

#include <TTD/IReplayEngine.h>
#include <TTD/IReplayEngineStl.h>
#include <TTD/ErrorReporting.h>

namespace analysis {
    // One write as handed to the reconstructor. `bytes` points into the log's arena, so a view
    // stays valid only while the log that produced it is alive and unmodified.
    struct WriteView {
        uint64_t address = 0;
        uint8_t const* bytes = nullptr;
        size_t length = 0;
    };

    // Every write observed inside one region.
    //
    // The per-write overhead is what decides whether a region can be reconstructed at all: a
    // packer that decrypts itself a few bytes at a time produces tens of millions of writes,
    // and giving each one its own std::vector costs a heap block plus ~32 bytes of header to
    // carry what is usually eight bytes of payload. Here the payloads share a single arena and
    // an event costs two integers. The only Position ever read back is the last one -- the
    // fallback generation marker in CodeScan -- so that is all that is kept.
    class WriteLog {
        public:
            WriteLog() : m_offsets{ 0 } {}

            void push(uint64_t address, TTD::Replay::Position const& position, uint8_t const* bytes, size_t length) {
                this->m_addresses.push_back(address);
                this->m_blob.insert(this->m_blob.end(), bytes, bytes + length);
                this->m_offsets.push_back(this->m_blob.size());
                this->m_lastPosition = position;
            }

            bool empty() const { return this->m_addresses.empty(); }
            size_t size() const { return this->m_addresses.size(); }

            WriteView operator[](size_t index) const {
                uint64_t const begin = this->m_offsets[index];
                return WriteView{
                    this->m_addresses[index],
                    this->m_blob.data() + begin,
                    static_cast<size_t>(this->m_offsets[index + 1] - begin),
                };
            }

            // Position of the most recent write, for the generation fallback
            TTD::Replay::Position const& lastPosition() const { return this->m_lastPosition; }

            // Host memory the log currently holds, counting reserved-but-unused capacity because
            // that is what the process has actually committed. The recording budget is checked
            // against this, and so is enforced to within the allocator's growth slack: the arena
            // grows geometrically, so crossing a capacity boundary transiently holds the old block
            // and the new one at once. Read a budget as "about this much", not a hard ceiling.
            uint64_t footprint() const {
                return static_cast<uint64_t>(this->m_addresses.capacity()) * sizeof(uint64_t)
                     + static_cast<uint64_t>(this->m_offsets.capacity()) * sizeof(uint64_t)
                     + static_cast<uint64_t>(this->m_blob.capacity());
            }

        private:
            std::vector<uint64_t> m_addresses;
            // size() + 1 entries: payload i is m_blob[m_offsets[i], m_offsets[i + 1])
            std::vector<uint64_t> m_offsets;
            std::vector<uint8_t> m_blob;
            TTD::Replay::Position m_lastPosition{};
    };
}

#endif
