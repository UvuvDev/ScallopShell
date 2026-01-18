#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Emits raw bytes for a switcher stub that increments a counter and dispatches
// to the chosen variant using an indirect call.
std::vector<uint8_t> emitSwitcherStub(
    const std::string& targetTriple,
    uint64_t counterAddr,
    uint64_t tableAddr,
    uint64_t variantCount);
