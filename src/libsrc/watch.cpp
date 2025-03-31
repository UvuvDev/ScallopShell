#include "watch.hpp"


/**
 * Watch memory, if memory's changed then return true.
 */
int watchMemory(pid_t child, uint64_t address, int nBytes)
{
    uint64_t data = ptrace(PTRACE_PEEKDATA, child, address, 0) >> 8 * (8 - nBytes);
    
    static uint64_t lastData = data;

    if (lastData != data)
    {
        lastData = data;
        return 1;
    }
    else
    {
        lastData = data;
        return 0;
    }
}

// Grrrrrr how do i pass the register
int watchRegister(pid_t child, unsigned long long reg) {

    static user_regs_struct data;

    ptrace(PTRACE_GETREGS, child, 0, &data);
    
    static user_regs_struct lastData = data;

    if (lastData.cs != data.cs)
    {
        lastData = data;
        return 1;
    }
    else
    {
        lastData = data;
        return 0;
    }

}