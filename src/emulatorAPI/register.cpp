#include "emulatorAPI.hpp"
#include "fstream"

static constexpr const char *kRegDump = "/tmp/regdump.txt";

std::vector<std::string> *Emulator::getRegisters()
{
    static bool tryagain = true;
    static std::vector<std::string> registers;

    const bool update_requested = getIsFlagQueued(0, VCPU_OP_DUMP_REGS);
    if (!update_requested && !tryagain)
    {
        return &registers;
    }

    // Request registers (either because a refresh was requested or we're still waiting on a retry)
    if (socket.sendCommand("get registers\n").compare(0, 2, "ok") != 0)
    {
        tryagain = true;
        return &registers;
    }

    // Open regdump
    std::ifstream regDump(kRegDump, std::ios::in);
    if (!regDump.is_open())
    {
        tryagain = true;
        return &registers;
    }

    std::vector<std::string> registersTemp;
    std::string line;
    while (std::getline(regDump, line))
    {
        if (!line.empty())
        {
            registersTemp.emplace_back(line);
        }
    }
    regDump.close();

    if (!registersTemp.empty())
    {
        registers = std::move(registersTemp);
        tryagain = false;
        if (update_requested)
        {
            removeFlag(0, VCPU_OP_DUMP_REGS);
        }
    }

    return &registers;
}

int Emulator::setRegister(std::string reg_name, uint64_t value)
{
    (void)reg_name;
    (void)value;
    return 0;
}
