#include "asm_dump.hpp"
#include "datastructs.hpp"
#include "gui.hpp"

cs_insn *insn;

// Keep track of backtrace, where we are in the program
AddressStack backtrace;
std::shared_ptr<LinkedList> jumpTable;

CliFlags flags;
bool runCliThisTick = false;
bool started = false;

void printInstructions(int j)
{
    int symbolI = hasSymbol(insn[j].address);
    int loopI = hasLoopSymbol(insn[j].address);

    if (loopI != -1)
    {

        if (memMaps.at(loopI).run < memMaps.at(loopI).maxrun)
        {

            if (insn[j].address == memMaps.at(loopI).bottomAddr)
                std::cout << BOLD_GREEN << "\n  #--------" << memMaps.at(loopI).desc << "--------#\n\n"
                          << RESET;

            // Print the instruction address, instruction and arguments
            printf("\t%s0x%" PRIx64 ":\t%s\t\t%s\n%s", GREEN, insn[j].address, insn[j].mnemonic,
                   insn[j].op_str, RESET);

            if (insn[j].address == memMaps.at(loopI).topAddr)
            {
                memMaps.at(loopI).run++;
                std::cout << BOLD_GREEN << "\n  #-------- end of " << memMaps.at(loopI).desc << "--------#\n\n"
                          << RESET;
            }
        }
    }

    else if (symbolI != -1)
    {
        // Check if the symbol table has any matches
        if (symbolTable.at(symbolI).getType() == 'b')
        {
            // Print the modified instruction with symbols
            std::cout << BOLD_BLUE << "  " << symbolTable.at(symbolI).getAddr() << ": " << insn[j].mnemonic << "\t\t" << insn[j].op_str << " |\t<- " << symbolTable.at(symbolI).getDesc() << RESET << "\n";
            Cli(&flags);
            runCliThisTick = true;
        }
        else if (symbolTable.at(symbolI).getType() == 's')
        {
            // Print the modified instruction with symbols
            std::cout << BOLD_MAGENTA << "  " << symbolTable.at(symbolI).getAddr() << ": " << insn[j].mnemonic << "\t\t" << insn[j].op_str << " |\t<- " << symbolTable.at(symbolI).getDesc() << RESET << "\n";
        }
    }
    else
    {

        if (hasInstrucBreak(insn[j].mnemonic) == 1)
        {
            std::cout << BOLD_MAGENTA << "  " << (uint64_t *)insn[j].address << ": " << insn[j].mnemonic << "\t\t" << insn[j].op_str << RESET << "\n";
            Cli(&flags);
            runCliThisTick = true;
            return;
        }

        // Print the instruction address, instruction and arguments
        std::cout << YELLOW << (uint64_t *)insn[j].address << ":\t" << BLUE
                  << insn[j].mnemonic << "\t\t" << MAGENTA << insn[j].op_str << "\n"
                  << RESET;
    }
}

void handleBacktrace(int j)
{
    if (!strncmp(insn[j].mnemonic, "ret", 3))
    {
        backtrace.pop();
    }
    if (!strncmp(insn[j].mnemonic, "call", 4))
    {
        backtrace.push(insn[j].address);
    }
}

int runFlags(int childPID)
{
    // Do flag operations
    switch (flags)
    {
    case CliFlags::ni:
        // If user wants to break at next instruction, break here
        if (!runCliThisTick)
        {
            Cli(&flags);
            return -1;
        }
        break;
    case CliFlags::contin:
        return -1;
        break;
    case CliFlags::printBack:
        backtrace.printStack();
        Cli(&flags);
        break;

    case CliFlags::breakpoint:

        uint64_t addr;
        char desc[30];
        char save[10];

        printf("\taddress  desc  saveToFile?  |  ");
        scanf("%lx %30s %10s", &addr, desc, save);
        clearLine();

        symbolTable.emplace_back(Symbol(addr, desc, 'b'));

        if (save[0] == 's')
        {
            FILE *symbolFile = fopen("ScallopSymbols.txt", "a");
            fprintf(symbolFile, "0x%lx %s b\n", addr, desc);
            fclose(symbolFile);
        }

        if (getchar() != EOF)
            ; // Clears the newline out of the buffer,
        // which prevents restarting of command

        Cli(&flags);

        break;
    case CliFlags::starti:
        // idk what to do here. restart the program but how?
        break;
    case CliFlags::clear:

        system("clear");
        Cli(&flags);

        break;
    case CliFlags::info:

        std::cout << "Process ID = " << childPID << "\n";
        Cli(&flags);

        break;
    }

    return 0;
}

bool moveOn()
{
    return (flags == CliFlags::contin);
}

int filterLinuxInit(pid_t child)
{
    char cmd[100];
    snprintf(cmd, 100, "cat /proc/%d/maps | grep \"ld-linux-x86-64.so\" ", child);
    FILE *map = popen(cmd, "r"); // Run a command that finds all GLIBC refs in /proc/##/maps

    {
        uint64_t lowerLibCTemp;
        uint64_t upperLibCTemp;
        while (fscanf(map, "%lx-%lx%*[^\n]\n", &lowerLibCTemp, &upperLibCTemp) == 2)
        {
            ignoredFunctions.emplace_back(std::make_pair(lowerLibCTemp, upperLibCTemp));
        }
    }

    fclose(map);

    return 0;
}

int filterLibC(pid_t child, int instructionsRun)
{
    // Check to see if LibC has been loaded yet
    if (instructionsRun % 100000 == 0 && !started)
    {

        /*== READ THE MEMORY MAP OF LIBC ==*/
        char cmd[100];
        snprintf(cmd, 100, "cat /proc/%d/maps | grep \"libc\" ", child);
        FILE *map = popen(cmd, "r"); // Run a command that finds all GLIBC refs in /proc/##/maps

        uint64_t lowerLibCTemp;
        uint64_t upperLibCTemp;
        uint64_t libcbase = UINT64_MAX;

        

        while (fscanf(map, "%lx-%lx%*[^\n]\n", &lowerLibCTemp, &upperLibCTemp) == 2)
        {
            ignoredFunctions.emplace_back(std::make_pair(lowerLibCTemp, upperLibCTemp));

            if (lowerLibCTemp < libcbase)
                libcbase = lowerLibCTemp;

        }

        pclose(map);

        /*== LOAD SYMBOL TABLE ==*/

        // Load the symbol table of LibC
        FILE *libc_symbols = popen("readelf -s /lib/x86_64-linux-gnu/libc.so.6", "r");
        if (libc_symbols == NULL)
        {
            return 1;
        }

        uint64_t libcaddr;
        char symbolName[256]; // Make sure the array is large enough
        char line[1024];
        int header_found = 0;

        // Process output line by line.
        while (fgets(line, sizeof(line), libc_symbols) != NULL)
        {
            // Look for the header line that begins the symbol table entries.
            if (!header_found)
            {
                if (strstr(line, "Num:") != NULL)
                {
                    header_found = 1; // Now the following lines are the entries.
                }
                continue; // Skip header lines.
            }

            if (sscanf(line, " %*d: %lx %*d %*s %*s %*s %*s %[^\n]", &libcaddr, symbolName) != 2)
            {
                continue;
            }
            //printf("Address: 0x%lx, Symbol: %s\n", libcaddr, symbolName);
            //printf("%lx\n", libcbase);
            symbolTable.emplace_back(Symbol(libcbase + libcaddr, symbolName, 's'));
        }

        pclose(libc_symbols);

    }
    return 0;
}

void isInLibC(uint64_t rip)
{

    int i = hasSymbol(rip);

    if (i != -1)
    {
        if (symbolTable.at(i).getDesc().find("GLIBC") == std::string::npos &&
            symbolTable.at(i).getDesc().find("glibc") == std::string::npos &&
            symbolTable.at(i).getDesc().find("GNU") == std::string::npos)
        {
            return;
        }
        else
        {
            std::cout << BOLD_BLUE << "In GLIBC at " << symbolTable.at(i).getDesc()
                      << "\n" << RESET;
        }
    }
}

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
    struct user_regs_struct regs;
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
                filterLibC(child, instructionsRun);
                whereami = isIgnored(ignoredFunctions, regs.rip);

                // If in LIBC or Kernel Module just skip
                if (whereami)
                {
                    cs_free(insn, count);
                    spinner();
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

                printInstructions(0);
                handleBacktrace(0);

                if (hasLoopSymbol(insn[0].address) == -1)
                {
                    while (!moveOn())
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