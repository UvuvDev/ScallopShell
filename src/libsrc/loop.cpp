#include "loop.hpp"
#include "datastructs.hpp"
#include "gui.hpp"
#include "jump.hpp"
#include "asm_dump.hpp"

cs_insn *insn;

// Keep track of backtrace, where we are in the program
AddressStack backtrace;
std::shared_ptr<LinkedList> jumpTable;

struct user_regs_struct regs;
CliFlags flags;
bool runCliThisTick = false;
bool started = false;

size_t disassemble(pid_t child, struct user_regs_struct *regs,
                   csh *handle, int *status,
                   bool run = true, cs_insn **insnArg = nullptr)
{

    int lastRIP = regs->rip;

    if (run)
    {
        if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) == -1)
        {
            perror("ptrace(PTRACE_SINGLESTEP)"); // Fail
            return -1;
        }

        waitpid(child, status, 0);

        if (WIFEXITED(*status))
        {
            printf("Program exited, breaking\n");
            return -1;
        }

        if (ptrace(PTRACE_GETREGS, child, nullptr, regs) == -1)
        {
            perror("ptrace(PTRACE_GETREGS)");
            return -1;
        }

        // Set the opcode
        unsigned long firstHalf = ptrace(PTRACE_PEEKDATA, child, (*regs).rip, nullptr);
        unsigned long secondHalf = ptrace(PTRACE_PEEKDATA, child, (*regs).rip + 8, nullptr);
        uint8_t opcode[16];
        assignOpcode(opcode, firstHalf, secondHalf);

        // Disassemble the opcode (max 16 bytes), telling it its at the addr $RIP
        return cs_disasm(*handle, opcode, 16, (*regs).rip, 0, &insn);
    }
    else
    {
        // Set the opcode
        unsigned long firstHalf = ptrace(PTRACE_PEEKDATA, child, (*regs).rip, nullptr);
        unsigned long secondHalf = ptrace(PTRACE_PEEKDATA, child, (*regs).rip + 8, nullptr);
        uint8_t opcode[16];
        assignOpcode(opcode, firstHalf, secondHalf);

        // Disassemble the opcode (max 16 bytes), telling it its at the addr $RIP
        return cs_disasm(*handle, opcode, 16, lastRIP, 0, insnArg);
    }
}

int assemblyDump(pid_t child)
{

    filterLinuxInit(child);

    // Parent process: wait for the child to stop.
    int status;
    csh handle;

    // If disassembler fails to open, break
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    waitpid(child, &status, 0); // Stop the child process until we start it again

    if (WIFSTOPPED(status))
    {
        std::cout << "Child stopped, now continuing execution." << std::endl;
        // Resume the child process.

        system("clear");

        bool whereami = 0;
        int instructionsRun = 0;
        uint64_t lastBack = backtrace.top();
        flags = CliFlags::ni;
        bool wasInLIBCLastInsn = false;

        FILE *asmDump = initFile("prog_asm.s");

        // While the program is running
        while (true)
        {

            size_t count = disassemble(child, &regs, &handle, &status);

            if ((signed long)count < 0)
            {
                break;
            }

            // If there was any instructions, ONLY PRINT THE FIRST ONE DISASSEMBLED
            if (count > 0)
            {

                instructionsRun++;
                runCliThisTick = false;

                // If instructionsRun % 1000 == 0 then check for LibC
                filterLibC(child, instructionsRun, started);
                whereami = isIgnored(ignoredFunctions, regs.rip);

                // If in LIBC or Kernel Module just skip
                if (whereami)
                {
                    cs_free(insn, count);
                    spinner();
                    if (started && !wasInLIBCLastInsn)
                        isInLibC(regs.rip);
                    wasInLIBCLastInsn = true;
                    continue;
                }

                wasInLIBCLastInsn = false;
                started = true;

                printInstructions();
                handleBacktrace();

                handleJumps(count);

                if (hasLoopSymbol(insn[0].address) == -1)
                {
                    while (true)
                    {
                        if (runFlags(child) == -1)
                            break;
                    }
                }

                saveInsnToFile(insn, asmDump);

                cs_free(insn, count);
            }
            else
            {
                printf(BLACK);
                printf("\tERROR: Failed to disassemble given code!\n");
                printf(RESET);
            }
        }

        fclose(asmDump);
        cs_close(&handle);
    }

    backtrace.printStack();
    // Wait until the child process finishes.
    waitpid(child, &status, 0);
    std::cout << "Child finished execution." << std::endl;

    return 0;
}