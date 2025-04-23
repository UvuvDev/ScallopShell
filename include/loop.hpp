#pragma once

#include "core.hpp"
#include "datastructs.hpp"
#include "gui.hpp"

extern cs_insn *insn;
// Keep track of backtrace, where we are in the program
extern AddressStack backtrace;
extern std::shared_ptr<LinkedList> jumpTable;

extern CliFlags flags;
extern bool runCliThisTick;
extern bool started;

size_t disassemble(pid_t child, struct user_regs_struct *regs,
    csh *handle, int *status,
    bool run, cs_insn **insnArg);


int assemblyDump(pid_t child);

