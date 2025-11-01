#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "memory"
#include "string"

enum class _EmulType {
    QEMU = 1,
    Gem5 = 2
};

enum class _EmulRetCode {
    SUCCESS = 0,
    ERROR = 1
};

// The class containing the emulator scallop shell runs
class Emulator {
private:

    std::string binaryPath;
    static bool isEmulating;

public:

    /**
     * Start emulating. Currently, QEMU is the only compatible emulator.
     */
    static int startEmulation(const std::string& executablePath);

    static int addBreakpoint(uint64_t address, std::string& comment);

    /**
     * Modify the memory from the address given until the address + n. 
     */
    static int modifyMemory(uint64_t address, uint8_t* data, int n);

    static int ignoreMemory(uint64_t lowAddress, uint64_t highAddress);

    /**
     * Retrieve memory from an address
     */
    static std::shared_ptr<uint8_t> getMemory(uint64_t address);

    /**
     * Get the value of a register
     */
    static uint64_t getRegister(std::string register);

    /**
     * Set the value of a register
     */
    static int setRegister(std::string register, uint64_t value);

    static std::shared_ptr<std::pair<uint64_t, uint64_t>> getInstructionJumpPaths(uint64_t address);
    
    static int step(int steps = 1);

    static std::string disassembleInstruction(uint64_t address, std::shared_ptr<uint8_t> data, int n = 16);

    static bool getIsEmulating();

};