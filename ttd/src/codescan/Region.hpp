#ifndef CODESCAN_REGION_HPP
#define CODESCAN_REGION_HPP

#include <cstdint>
#include <map>
#include <vector>

namespace discovery {
    enum class Classification { Data, Executable };

    // Every PAGE_EXECUTE* protection constant lives in this nibble
    inline constexpr uint32_t ExecutableProtectionMask = 0xF0;
    // PAGE_EXECUTE_READ, spelled out so that this header stays free of <windows.h>
    inline constexpr uint32_t ExecuteReadProtection = 0x20;

    struct Region {
        uint64_t base = 0;
        uint64_t size = 0;
        uint32_t protection = 0;
        Classification classification() const {
            return (protection & ExecutableProtectionMask) ? Classification::Executable : Classification::Data;
        }
        bool isExecutable() const { return this->classification() == Classification::Executable; }
        uint64_t end() const { return this->base + this->size; }
    };

    // Used to track EVERY memory region in the trace
    class MemoryRegions {
        public:
            using Map = std::map<uint64_t, Region>;

            // Adds a region. Returns false if it overlaps one that is already tracked.
            bool addRegion(Region r);
            // Checks if a given chunk of memory overlaps with any existing region
            bool overlapsExisting(uint64_t base, uint64_t size) const;
            // Retrieves every region overlapping [low, high)
            std::vector<Region*> overlapping(uint64_t low, uint64_t high);
            // Flags regions overlapping [base, base + size) executable, returning how many changed
            size_t reclassifyExecutable(uint64_t base, uint64_t size);

            bool empty() const { return this->m_byBase.empty(); }
            size_t size() const { return this->m_byBase.size(); }

            // Iteration is ordered by base address, for write collection and reporting loops
            Map::const_iterator begin() const { return this->m_byBase.begin(); }
            Map::const_iterator end() const { return this->m_byBase.end(); }
        private:
            // Maps base address to tracked memory regions
            Map m_byBase;
            // Size of largest memory region. Used for overlap back-scan
            uint64_t m_maxRegionSize = 0;
    };
}

#endif
