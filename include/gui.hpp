#pragma once
#include "core.hpp"
// add to the top of this file (or a shared header)
#include <string>
#include <optional>
#include <sstream>
#include <cctype>
#include <cstring>

#include <deque>
#include <mutex>
#include <thread>
#include <atomic>

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>

#include <CLI11/CLI11.hpp>

// gui.hpp (or a shared header)
extern std::atomic<bool> g_continue_mode;   // true = run freely, false = pause each insn
extern std::atomic<bool> g_quit;


void UiStart();                  // start FTXUI in its own loop
void UiStop();                   // optional: graceful shutdown
void UiLog(const std::string&);  // append a line to the instruction panel
void UiLogRaw(const std::string& s); // same, no post-processing (optional)
void UiClear();                  // clear the instruction panel
bool UiPopCommand(std::string&); // non-blocking: get next user command if any

// Optional helpers if you want “status” line or right-side panes later:
void UiSetStatus(const std::string& line); // single status line under log


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
    pFlags = 11,
    examine = 12,
    stopGLIBCprints = 13,
    startGLIBCprints = 14
};

enum class ExamineFlags {
    b = 1,
    h = 2, 
    w = 4, 
    g = 8
};

extern ExamineFlags xFlags;


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
