#include "main.hpp"
#include <algorithm>
#include <unordered_map>

std::vector<uint8_t> buildMemoryImage(
    const std::vector<instructionData>& insns,
    uint64_t& base,
    uint64_t& entry,
    uint8_t pad) {
    base = 0;
    entry = 0;

    if (insns.empty()) {
        return {};
    }

    // First PC is the entry point (caller requested).
    entry = insns.front().pc;

    // Deduplicate by PC while tracking bounds.
    std::unordered_map<uint64_t, std::vector<uint8_t>> by_pc;
    uint64_t min_pc = UINT64_MAX;
    uint64_t max_end = 0;

    for (const auto& insn : insns) {
        if (insn.bytes.empty())
            continue;

        auto inserted = by_pc.emplace(insn.pc, insn.bytes);
        if (!inserted.second) {
            // Keep the first occurrence to preserve original ordering semantics.
            continue;
        }

        if (insn.pc < min_pc)
            min_pc = insn.pc;

        const uint64_t end = insn.pc + static_cast<uint64_t>(insn.bytes.size());
        if (end > max_end)
            max_end = end;
    }

    if (by_pc.empty() || min_pc == UINT64_MAX || max_end <= min_pc) {
        base = 0;
        return {};
    }

    base = min_pc;
    const uint64_t size = max_end - min_pc;
    std::vector<uint8_t> image(static_cast<size_t>(size), pad);

    for (const auto& kv : by_pc) {
        const uint64_t pc = kv.first;
        const auto& bytes = kv.second;
        const uint64_t off = pc - min_pc;
        if (off + bytes.size() > image.size())
            continue;
        std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<size_t>(off));
    }

    return image;
}
