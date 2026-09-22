#ifndef CODESCAN_SHADOWRECONSTRUCTOR_HPP
#define CODESCAN_SHADOWRECONSTRUCTOR_HPP

#include "WriteLog.hpp"

#include <cstdint>
#include <vector>

namespace analysis {
    // Replays a region's writes into a host-side buffer. In trace order this gives "last write
    // wins", reproducing the region's contents as of any point in the log.
    //
    // Unwritten bytes stay zero, so a byte explicitly written as 0x00 is indistinguishable from an
    // untouched one.
    class ShadowReconstructor {
        public:
            // A write intersected with the region: where it lands, how many bytes survive, and
            // where those bytes start within the write itself.
            struct Clip {
                uint64_t offset = 0;
                uint64_t length = 0;
                uint64_t sourceOffset = 0;
            };

            ShadowReconstructor(uint64_t regionBase, uint64_t regionSize);

            // Start from `initial` rather than zeros, for a region whose contents did not
            // arrive as writes. A fresh allocation really does start empty, but a mapped
            // image does not: the loader put it there before anything we watch happened,
            // so a module reconstructed from writes alone is a PE with no PE header --
            // precisely the unpacked sample, minus everything that identifies it as one.
            // Bytes past the end of `initial` are left as they are.
            void seed(std::vector<uint8_t> const& initial);

            // Clips a write to the region. Returns false when it lands entirely outside.
            bool clip(WriteView const& write, Clip& clipped) const;
            // Copies a write's bytes in, using the clip the caller already computed. Returns
            // whether any byte of the region actually changed value, which is how a caller
            // tells two generations apart without comparing whole regions.
            bool apply(WriteView const& write, Clip const& clipped);

            // True when any byte in [offset, offset + length) is currently non-zero
            bool anyNonZero(uint64_t offset, uint64_t length) const;
            // True when any byte of the whole region is currently non-zero
            bool hasNonZero() const { return this->m_nonZeroBytes > 0; }

            uint8_t const* data() const { return this->m_shadow.data(); }
            size_t size() const { return this->m_shadow.size(); }
        private:
            uint64_t m_base = 0;
            std::vector<uint8_t> m_shadow;
            // Tracked incrementally so "is this snapshot worth scanning?" stays O(1)
            uint64_t m_nonZeroBytes = 0;
    };
}

#endif
