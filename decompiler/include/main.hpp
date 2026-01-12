#include <stdio.h>
#include "stdint.h"
#include "vector"
#include "string"

struct instructionData {
    uint64_t pc;
    uint64_t branchTarget;
    uint64_t fallthroughAddr;
    uint64_t translatedBlockBase;
    std::vector<uint8_t> bytes;
    std::string disassembly;
    std::string symbol;
};