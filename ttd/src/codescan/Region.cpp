#include "Region.hpp"

#include <algorithm>

using namespace discovery;

// Regions are keyed by base, so only those starting at or after (low - largest region seen) and
// before high can overlap. Walking that window keeps lookups logarithmic rather than linear.
static uint64_t backScanStart(uint64_t low, uint64_t maxRegionSize) {
    return (low > maxRegionSize) ? (low - maxRegionSize) : 0;
}

bool MemoryRegions::addRegion(Region region) {
    if (region.size == 0) return false;
    if (this->overlapsExisting(region.base, region.size)) return false;

    this->m_maxRegionSize = (std::max)(this->m_maxRegionSize, region.size);
    this->m_byBase[region.base] = region;

    return true;
}

bool MemoryRegions::overlapsExisting(uint64_t base, uint64_t size) const {
    if (size == 0) return false;

    uint64_t const high = base + size;
    auto it = this->m_byBase.lower_bound(backScanStart(base, this->m_maxRegionSize));

    for (; it != this->m_byBase.end() && it->first < high; ++it) {
        if (it->second.end() > base) return true;
    }

    return false;
}

std::vector<Region*> MemoryRegions::overlapping(uint64_t low, uint64_t high) {
    std::vector<Region*> hits;
    if (low >= high) return hits;

    auto it = this->m_byBase.lower_bound(backScanStart(low, this->m_maxRegionSize));

    for (; it != this->m_byBase.end() && it->first < high; ++it) {
        if (it->second.end() > low) hits.push_back(&(it->second));
    }

    return hits;
}

size_t MemoryRegions::reclassifyExecutable(uint64_t base, uint64_t size) {
    size_t reclassified = 0;

    for (Region* region : this->overlapping(base, base + size)) {
        if (region->isExecutable()) continue;  // already executable; nothing to report

        region->protection |= ExecuteReadProtection;
        ++reclassified;
    }

    return reclassified;
}
