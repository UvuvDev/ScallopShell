#include "emulatorAPI.hpp"

int Emulator::step(int steps)
{
    if (hasStagedMemoryWrite())
    {
        setFlag(0, VCPU_OP_SET_MEM);
        if (flushStagedMemoryWrite() != 0)
        {
            fprintf(stderr, "[scallop] failed to stage memory write\n");
            removeFlag(0, VCPU_OP_SET_MEM);
        }
    }

    std::string ret;
    bool exitCode = socket.sendCommand(std::string("step ") + std::to_string(steps)).compare(0, 2, "ok") != 0;
    setFlag(0, VCPU_OP_DUMP_MEM);
    setFlag(0, VCPU_OP_DUMP_REGS);
    setFlag(0, VCPU_OP_SET_REGS);
    getRegisters();
    return exitCode;
}

int Emulator::continueExec()
{
    if (hasStagedMemoryWrite())
    {
        setFlag(0, VCPU_OP_SET_MEM);
        if (flushStagedMemoryWrite() != 0)
        {
            fprintf(stderr, "[scallop] failed to stage memory write\n");
            removeFlag(0, VCPU_OP_SET_MEM);
        }
    }

    std::string ret;
    bool exitCode = socket.sendCommand("resume").compare(0, 2, "ok") != 0;
    setFlag(0, VCPU_OP_DUMP_MEM);
    setFlag(0, VCPU_OP_DUMP_REGS);
    setFlag(0, VCPU_OP_SET_REGS);
    return exitCode;
}

int Emulator::focusMemory(uint64_t lowAddress, uint64_t highAddress)
{
    std::string ret;
    std::string exit = socket.sendCommand(std::to_string(lowAddress) + ';' + std::to_string(highAddress) + '\n');
    return 0;
}
