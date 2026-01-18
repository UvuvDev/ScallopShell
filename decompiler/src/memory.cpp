#include "main.hpp"
#include "switcher.hpp"
#include <algorithm>
#include <unordered_map>
#include <stdexcept>

std::vector<uint8_t> buildMemoryImage(
    const std::vector<instructionData>& insns,
    uint64_t& base,
    uint64_t& entry,
    uint8_t pad,
    const std::string& targetTriple) {
    base = 0;
    entry = 0;

    if (insns.empty()) {
        return {}; 
    }

    // First PC is the entry point (caller requested).
    entry = insns.front().pc;

    struct VariantChunk {
        uint64_t start_pc;
        std::vector<uint8_t> bytes;
    };
    struct VariantGroup {
        uint64_t pc;
        std::vector<VariantChunk> variants;
    };

    uint64_t min_pc = UINT64_MAX;
    uint64_t max_end = 0;

    for (const auto& insn : insns) {
        if (insn.bytes.empty())
            continue;

        // Set the lowest bound of the PC
        if (insn.pc < min_pc)
            min_pc = insn.pc;

        // Minimum PC + Total Size = End PC
        const uint64_t end = insn.pc + static_cast<uint64_t>(insn.bytes.size());
        if (end > max_end)
            max_end = end;
    }

    if (min_pc == UINT64_MAX || max_end <= min_pc) {
        base = 0;
        return {};
    }

    auto buildVariantGroups = [&]() {
        std::unordered_map<uint64_t, std::vector<VariantChunk>> by_pc;
        for (size_t i = 0; i < insns.size(); ++i) {
            const auto& insn = insns[i];
            if (insn.bytes.empty())
                continue;

            VariantChunk chunk{insn.pc, insn.bytes};
            uint64_t expected = insn.fallthroughAddr;
            size_t j = i;
            while (j + 1 < insns.size()) {
                const auto& next = insns[j + 1];
                if (next.bytes.empty() || next.pc != expected)
                    break;
                chunk.bytes.insert(chunk.bytes.end(), next.bytes.begin(), next.bytes.end());
                expected = next.fallthroughAddr;
                ++j;
            }
            by_pc[insn.pc].push_back(std::move(chunk));
            i = j;
        }

        std::vector<VariantGroup> groups;
        groups.reserve(by_pc.size());
        for (auto& kv : by_pc) {
            groups.push_back(VariantGroup{kv.first, std::move(kv.second)});
        }
        std::sort(groups.begin(), groups.end(),
                  [](const VariantGroup& a, const VariantGroup& b) { return a.pc < b.pc; });
        return groups;
    };

    const auto groups = buildVariantGroups();

    base = min_pc;
    const uint64_t original_size = max_end - min_pc;
    if (targetTriple.empty()) {
        for (const auto& group : groups) {
            if (group.variants.size() > 1) {
                throw std::runtime_error("targetTriple is required for switcher stubs");
            }
        }
    }

    struct SwitcherLayout {
        uint64_t pc;
        std::vector<uint64_t> variant_addrs;
        uint64_t counter_addr = 0;
        uint64_t table_addr = 0;
        std::vector<uint8_t> stub_bytes;
    };

    uint64_t arena_base = max_end;
    uint64_t arena_cursor = arena_base;
    std::vector<SwitcherLayout> switchers;
    switchers.reserve(groups.size());

    for (const auto& group : groups) {
        if (group.variants.size() <= 1)
            continue;

        SwitcherLayout layout;
        layout.pc = group.pc;
        for (const auto& variant : group.variants) {
            std::cout << "PC = " << (void*)layout.pc << "  Counter Addr " << (void*)layout.counter_addr << "   Table Addr" << (void*)layout.table_addr << "   " << std::endl;
            for (auto& j : layout.variant_addrs) {
                std::cout << (void*)j;
            }
            std::cout << std::endl;
            layout.variant_addrs.push_back(arena_cursor);
            arena_cursor += variant.bytes.size();
        }
        switchers.push_back(std::move(layout));
    }

    auto alignUp = [](uint64_t value, uint64_t align) {
        return (value + align - 1) & ~(align - 1);
    };

    uint64_t counters_base = alignUp(arena_cursor, 8);
    for (size_t i = 0; i < switchers.size(); ++i) {
        switchers[i].counter_addr = counters_base + i * 8;
    }

    uint64_t tables_base = alignUp(counters_base + switchers.size() * 8, 8);
    uint64_t table_cursor = tables_base;
    for (auto& sw : switchers) {
        sw.table_addr = table_cursor;
        table_cursor += sw.variant_addrs.size() * 8;
    }

    const uint64_t final_end = table_cursor;
    const uint64_t size = final_end - min_pc;
    std::cout << size << std::endl;
    std::vector<uint8_t> image(static_cast<size_t>(size), pad);
    std::vector<uint8_t> occupied(static_cast<size_t>(original_size), 0);

    for (auto& sw : switchers) {
        sw.stub_bytes = emitSwitcherStub(targetTriple, sw.counter_addr, sw.table_addr,
                                         sw.variant_addrs.size());
        const uint64_t off = sw.pc - min_pc;
        if (off + sw.stub_bytes.size() > image.size())
            continue;
        std::copy(sw.stub_bytes.begin(), sw.stub_bytes.end(),
                  image.begin() + static_cast<size_t>(off));

        const uint64_t occ_end = std::min<uint64_t>(off + sw.stub_bytes.size(), original_size);
        for (uint64_t i = off; i < occ_end; ++i) {
            occupied[static_cast<size_t>(i)] = 1;
        }
    }

    for (const auto& group : groups) {
        if (group.variants.size() != 1)
            continue;
        const auto& chunk = group.variants.front();
        const uint64_t off = chunk.start_pc - min_pc;
        if (off + chunk.bytes.size() > image.size())
            continue;
        for (size_t i = 0; i < chunk.bytes.size(); ++i) {
            const uint64_t pos = off + i;
            if (pos < occupied.size() && occupied[static_cast<size_t>(pos)])
                continue;
            image[static_cast<size_t>(pos)] = chunk.bytes[i];
        }
    }

    for (size_t gi = 0, si = 0; gi < groups.size(); ++gi) {
        const auto& group = groups[gi];
        if (group.variants.size() <= 1)
            continue;
        auto& sw = switchers[si++];

        for (size_t vi = 0; vi < group.variants.size(); ++vi) {
            const auto& chunk = group.variants[vi];
            const uint64_t dst = sw.variant_addrs[vi];
            const uint64_t off = dst - min_pc;
            if (off + chunk.bytes.size() > image.size())
                continue;
            std::copy(chunk.bytes.begin(), chunk.bytes.end(),
                      image.begin() + static_cast<size_t>(off));
        }
    }

    for (const auto& sw : switchers) {
        const uint64_t counter_off = sw.counter_addr - min_pc;
        if (counter_off + 8 <= image.size()) {
            for (size_t i = 0; i < 8; ++i) {
                image[static_cast<size_t>(counter_off + i)] = 0;
            }
        }
        const uint64_t table_off = sw.table_addr - min_pc;
        for (size_t i = 0; i < sw.variant_addrs.size(); ++i) {
            const uint64_t entry_off = table_off + i * 8;
            if (entry_off + 8 > image.size())
                continue;
            const uint64_t addr = sw.variant_addrs[i];
            for (size_t b = 0; b < 8; ++b) {
                image[static_cast<size_t>(entry_off + b)] =
                    static_cast<uint8_t>((addr >> (8 * b)) & 0xFF);
            }
        }
    }

    return image;
}
