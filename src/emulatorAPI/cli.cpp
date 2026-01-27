#include "emulatorAPI.hpp"

std::atomic_uint64_t Emulator::flags[MAX_VCPUS];

int Emulator::setFlag(int vcpu, vcpu_operation_t cmd) {
    // Set the flag to be the cmd
    flags[vcpu].store(flags[vcpu].load(std::memory_order_relaxed) | cmd, std::memory_order_relaxed); 

    // Get how many shifts the flag was at ( 0b01000 would = 3 )
    uint64_t flagIndex = std::countr_zero(static_cast<uint64_t>(cmd));

    return 0;
}

int Emulator::removeFlag(int vcpu, vcpu_operation_t cmd) {
    // FLAGS AND (FLAGS AND NOT CMD) = turning off only the inputted flag
    flags[vcpu].store(flags[vcpu].load(std::memory_order_relaxed) & (~cmd), std::memory_order_relaxed);
    return 0;
}

bool Emulator::getIsFlagQueued(int vcpu, vcpu_operation_t cmd) {
    return (flags[vcpu].load(std::memory_order_relaxed) & cmd) == cmd;
}

int Emulator::addBreakpoint(uint64_t address, std::string &comment)
{
    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "break 0x%llx %d %s\n",
                  address, selectedVCPU, selectedThread.c_str());

    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    return 0;
}

int Emulator::deleteBreakpoint(uint64_t address)
{
    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "unbreak 0x%llx %d %s\n",
                  address, selectedVCPU, selectedThread.c_str());
    std::cerr << "[cli] send delete breakpoint: " << cmd;

    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    return 0;
}
