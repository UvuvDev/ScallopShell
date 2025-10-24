#include "emulatorAPI.hpp"



int Emulator::startEmulation(std::string& executablePath) {
    executablePath = executablePath;
    return 0;
}

int Emulator::addBreakpoint(uint64_t address, std::string& comment) {
    address = 0;
    comment = comment;
    return 0;
}

int Emulator::modifyMemory(uint64_t address, std::shared_ptr<uint8_t> data, int n) {
    address = 0;
    data = nullptr;
    n = 0;
    return 0;
}

int Emulator::ignoreMemory(uint64_t lowAddress, uint64_t highAddress) {
    lowAddress = 0;
    highAddress = 0;
    return 0;
}

std::shared_ptr<uint8_t> Emulator::getMemory(uint64_t address) {
    address = 0;
    return nullptr;
}

uint64_t Emulator::getRegister(std::string register) {
    
    return 0;
}

int Emulator::setRegister(std::string register, uint64_t data) {
    return 0;
}


std::shared_ptr<std::pair<uint64_t, uint64_t>> Emulator::getInstructionJumpPaths(uint64_t address) {
    address = 0;
    return nullptr;
}
    
int Emulator::step(int steps) {
    steps = 0;
    return 0;
}

std::string Emulator::disassembleInstruction(uint64_t address, std::shared_ptr<uint8_t> data, int n) {
    address = 0;
    data = nullptr;
    n = 0;
    return nullptr;
}

