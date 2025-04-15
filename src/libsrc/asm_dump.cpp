#include "asm_dump.hpp"
#include "datastructs.hpp"
#include "gui.hpp"

cs_insn *insn;

// Keep track of backtrace, where we are in the program
AddressStack backtrace;
std::shared_ptr<LinkedList> jumpTable;

struct user_regs_struct regs;
CliFlags flags;
bool runCliThisTick = false;
bool started = false;


size_t disassemble(pid_t child, struct user_regs_struct *regs,
                   csh *handle, int *status, int *paddingLen,
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

        *paddingLen = regs->rip - lastRIP;

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

        *paddingLen = regs->rip - lastRIP;

        // Disassemble the opcode (max 16 bytes), telling it its at the addr $RIP
        return cs_disasm(*handle, opcode, 16, lastRIP, 0, insnArg);
    }
}
/*
bool jumpOccurred(user_regs_struct *regs, uint64_t *jmpAddrArg,
        uint64_t *stayAddrArg, uint64_t lastRIP,
        int paddingLen, pid_t child)
{

    csh tempHandler;
    cs_insn* tempInsn;
    user_regs_struct tempReg;
    int status;

    // If disassembler fails to open, break
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &tempHandler) != CS_ERR_OK)
        return -1;

    // Disassemble
    int cnt = disassemble(child, &tempReg, &tempHandler, &status, &paddingLen, false, &tempInsn);


    *stayAddrArg = lastRIP;

    // Jump didn't occur. Set Jmp Addr to 0 and stayAddrArg to
    if (cnt > 0 && lastRIP + tempInsn[0].size == regs->rip)
    {
        *jmpAddrArg = 0;
        return false;
    }
    else if (cnt > 1 && lastRIP + tempInsn[0].size + tempInsn[1].size == regs->rip) {
        *jmpAddrArg = 0;
        return false;
    }
    else
    {
        *jmpAddrArg = regs->rip;
        // printf("stayaddr = 0x%lx\t\tjmpaddr = 0x%lx", *stayAddrArg, *jmpAddrArg);
        return true;
    }

    cs_close(&tempHandler);

}*/

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

        // While the program is running
        while (true)
        {

            uint64_t lastRIP = regs.rip;
            int paddingLen;

            size_t count = disassemble(child, &regs, &handle, &status, &paddingLen);

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
                    if (started)
                        isInLibC(regs.rip);
                    continue;
                }

                started = true;

                /*uint64_t jmpAddr;
                uint64_t stayAddr;
                bool jumped = jumpOccurred(&regs, &jmpAddr, &stayAddr, lastRIP, paddingLen, child);

                // If theres a jump instruction
                if (jumped)
                {

                    std::shared_ptr<LinkedList> lastNode = jumpTable;
                    int length = 0;

                    uint64_t jmpAddr = regs.rip;
                    // printf("\n\n");
                    bool duplicateFound = false;

                    while (lastNode != NULL && lastNode->next != NULL)
                    {
                        if (lastNode->jmpAddr == jmpAddr)
                        {
                            lastNode->next = NULL;
                            duplicateFound = true;
                            break;
                        }
                        else if (lastNode->stayAddr == stayAddr)
                        {
                            lastNode->next = NULL;
                            duplicateFound = true;
                            break;
                        }
                        // printf(" 0x%lx -> ", lastNode->jmpAddr);
                        length++;
                        lastNode = lastNode->next;
                    }

                    if (!duplicateFound)
                    {
                        std::shared_ptr<LinkedList> newNode = std::make_shared<LinkedList>(nullptr, jmpAddr, stayAddr);
                        // printf("new addr = %lx", jmpAddr);
                        if (jumpTable == NULL)
                        {
                            jumpTable = newNode;
                        }
                        else
                        {
                            lastNode->next = newNode;
                        }
                    }

                    jumpTable->printList();

                    // printf("\n\n");

                    printInstructions(0);
                    handleBacktrace(0);
                }*/

                printInstructions();
                handleBacktrace();

                if (hasLoopSymbol(insn[0].address) == -1)
                {
                    while (true)
                    {
                        if (runFlags(child) == -1)
                            break;
                    }
                }

                cs_free(insn, count);
            }
            else
            {
                printf(BLACK);
                printf("\tERROR: Failed to disassemble given code!\n");
                printf(RESET);
            }
        }

        cs_close(&handle);
    }

    backtrace.printStack();
    // Wait until the child process finishes.
    waitpid(child, &status, 0);
    std::cout << "Child finished execution." << std::endl;

    return 0;
}