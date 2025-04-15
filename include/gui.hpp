#pragma once
#include "core.hpp"
#include <iomanip>

enum class CliFlags {
    def = 0,
    contin = 1,
    printBack = 2,
    ni = 3,
    breakpoint = 4,
    lay = 5,
    starti = 6,
    clear = 7,
    info = 8,
    regV = 9,
    regC = 10,
    pFlags = 11
};

int Cli(CliFlags* flags);
void spinner();
void clearLine();

// Print instructions
void printMemMap(int index);
void printBreak(int symbolI);
void printSymbol(int symbolI);
void printBasic();
void printInstructions();

void printRegVerbose(user_regs_struct* regs);

void examineReg(user_regs_struct* regs, std::string& userInput);

void handleBacktrace();

bool moveOn();

int runFlags(int childPID);
