#include "filter.hpp"

std::vector<std::string> branches = {"call", "jmp", "ret"};
int shouldBranch(instructionData insn) {

    for (auto& branchKind : branches) {
        if (insn.kind == branchKind) return 1;
    }

    return 0;
}