#pragma once

#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <memory.h>
#include <fstream>
#include <iostream>
#include <cstring>

#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/personality.h>

#include "capstone/capstone.h"
#include "eventhandler.hpp"

// Reset all attributes
#define RESET "\033[0m"

// Regular Colors
#define BLACK "\033[30m"
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define WHITE "\033[37m"

// Bold Colors
#define BOLD_BLACK "\033[1;30m"
#define BOLD_RED "\033[1;31m"
#define BOLD_GREEN "\033[1;32m"
#define BOLD_YELLOW "\033[1;33m"
#define BOLD_BLUE "\033[1;34m"
#define BOLD_MAGENTA "\033[1;35m"
#define BOLD_CYAN "\033[1;36m"
#define BOLD_WHITE "\033[1;37m"
#define BOLD_CRIMSON    "\033[38;5;160m"  // A deep red (crimson)
#define BOLD_FIREBRICK  "\033[38;5;124m"  // Another intense deep red (firebrick)
#define BOLD_TANGERINE  "\033[38;5;214m"  // A bright, vibrant orange (tangerine)
#define BOLD_AMBER      "\033[38;5;220m"  // A warm amber (yellow-orange)
#define BOLD_GOLD       "\033[38;5;178m"  // A soft, warm golden yellow

// Underline Colors
#define UNDERLINE_BLACK "\033[4;30m"
#define UNDERLINE_RED "\033[4;31m"
#define UNDERLINE_GREEN "\033[4;32m"
#define UNDERLINE_YELLOW "\033[4;33m"
#define UNDERLINE_BLUE "\033[4;34m"
#define UNDERLINE_MAGENTA "\033[4;35m"
#define UNDERLINE_CYAN "\033[4;36m"
#define UNDERLINE_WHITE "\033[4;37m"

// Background Colors
#define BG_BLACK "\033[40m"
#define BG_RED "\033[41m"
#define BG_GREEN "\033[42m"
#define BG_YELLOW "\033[43m"
#define BG_BLUE "\033[44m"
#define BG_MAGENTA "\033[45m"
#define BG_CYAN "\033[46m"
#define BG_WHITE "\033[47m"

typedef char SymbolType;

class Symbol
{

    std::string desc;
    uint64_t *addr;
    SymbolType type;

public:
    Symbol(uint64_t addr, std::string desc, SymbolType type)
    {
        this->addr = (uint64_t *)addr;
        this->desc = desc;
        this->type = type;
    }
    Symbol(uint64_t addr, char *desc, SymbolType type)
    {
        this->addr = (uint64_t *)addr;
        this->desc = desc;
        this->type = type;
    }

    uint64_t *getAddr()
    {
        return addr;
    }

    std::string &getDesc()
    {
        return desc;
    }

    SymbolType getType()
    {
        return type;
    }
};

typedef std::vector<Symbol> SymbolTable;

class MemMap
{
public:
    uint64_t bottomAddr;
    uint64_t topAddr;
    char type;
    int run;
    int maxrun;
    std::string desc;

    MemMap(uint64_t bottomAddr,
           uint64_t topAddr,
           std::string desc,
           char type, int maxrun)
    {
        this->bottomAddr = bottomAddr;
        this->topAddr = topAddr;
        this->type = type;
        this->desc = desc;
        this->maxrun = maxrun;
        this->run = 0;
    }

    MemMap(uint64_t bottomAddr,
           uint64_t topAddr,
           char* desc,
           char type, int maxrun)
    {
        this->bottomAddr = bottomAddr;
        this->topAddr = topAddr;
        this->type = type;
        this->desc = desc;
        this->maxrun = maxrun;
        this->run = 0;
    }

    bool canRun() {
        if (maxrun < 0) return true;

        if (run < maxrun) return true;

        return false;
    }
};

/*===== GLOBAL VARIABLE DEFS =====*/

//
extern std::vector<std::pair<uint64_t, uint64_t>> ignoredFunctions;
//
extern std::vector<Symbol> symbolTable;
//
extern std::vector<MemMap> memMaps;
extern struct user_regs_struct regs;
extern pid_t child;
extern bool printGLIBC;

/*================================*/

/**
 * Make the opcode array given data
 */
void assignOpcode(uint8_t *opcode, int firstHalf, int secondHalf);
/**
 * Display README.md
 */
void startupMsg();
int isAscii(char *str, int n);
/**
 * Prefix the arg with a ./
 */
char *makeFilepath(char *argv);
/**
 * Check if the address has a value on the symbol table. Return vector index, -1 if fail.
 */
int hasSymbol(uint64_t address);

int hasLoopSymbol(uint64_t address);

/**
 * Check if the instruction has a break on run (defined by an addr of 0xF0)
 */
int hasInstrucBreak(char *instruction);

bool isIgnored(std::vector<std::pair<uint64_t, uint64_t>> range, uint64_t addr);


int filterLinuxInit(pid_t child);

int filterLibC(pid_t child, int instructionsRun, bool started);

void isInLibC(uint64_t rip);