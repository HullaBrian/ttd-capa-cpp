#include "ShadowReconstructor.hpp"

#include <algorithm>
#include <cstring>

using namespace analysis;

ShadowReconstructor::ShadowReconstructor(uint64_t regionBase, uint64_t regionSize)
    : m_base(regionBase)
    , m_shadow(static_cast<size_t>(regionSize), 0)
{}

void ShadowReconstructor::seed(std::vector<uint8_t> const& initial) {
    size_t const length = (std::min)(initial.size(), this->m_shadow.size());
    if (length == 0) return;

    std::memcpy(this->m_shadow.data(), initial.data(), length);
    // Recount rather than adjust: this runs once per region, and the alternative is a
    // second place that has to keep m_nonZeroBytes in step with the buffer.
    this->m_nonZeroBytes = static_cast<uint64_t>(
        std::count_if(this->m_shadow.begin(), this->m_shadow.end(),
                      [](uint8_t byte) { return byte != 0; }));
}

bool ShadowReconstructor::clip(WriteView const& write, Clip& clipped) const {
    uint64_t const writeLow = write.address;
    uint64_t const low = (std::max)(writeLow, this->m_base);
    uint64_t const high = (std::min)(writeLow + write.length, this->m_base + this->m_shadow.size());
    if (low >= high) return false;

    clipped.offset = low - this->m_base;
    clipped.length = high - low;
    clipped.sourceOffset = low - writeLow;

    return true;
}

bool ShadowReconstructor::apply(WriteView const& write, Clip const& clipped) {
    uint8_t const* source = write.bytes + clipped.sourceOffset;
    uint8_t* destination = this->m_shadow.data() + clipped.offset;
    size_t const length = static_cast<size_t>(clipped.length);

    // A write that stores the bytes already there leaves the region identical -- a decryptor
    // re-running over ground it has covered, a loop restoring a constant. Saying so costs one
    // comparison over a handful of bytes and saves the caller a compare over the whole region.
    if (std::memcmp(destination, source, length) == 0) return false;

    // Count in bulk rather than per byte: both counts vectorize, and the copy below becomes a
    // plain memcpy instead of a branch per byte on what is the hottest loop in the pipeline.
    int64_t const zerosBefore = std::count(destination, destination + length, uint8_t{ 0 });
    int64_t const zerosAfter = std::count(source, source + length, uint8_t{ 0 });
    int64_t const delta = zerosBefore - zerosAfter;  // bytes that just became non-zero, less those that became zero

    if (delta >= 0) this->m_nonZeroBytes += static_cast<uint64_t>(delta);
    else this->m_nonZeroBytes -= static_cast<uint64_t>(-delta);

    std::memcpy(destination, source, length);
    return true;
}

bool ShadowReconstructor::anyNonZero(uint64_t offset, uint64_t length) const {
    if (this->m_nonZeroBytes == 0) return false;  // nothing in the region is set at all
    if (offset >= this->m_shadow.size()) return false;

    length = (std::min)(length, this->m_shadow.size() - offset);
    uint8_t const* start = this->m_shadow.data() + static_cast<size_t>(offset);

    return std::any_of(start, start + length, [](uint8_t byte) { return byte != 0; });
}
