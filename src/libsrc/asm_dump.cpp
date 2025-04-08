#include "asm_dump.hpp"
#include "datastructs.hpp"
#include "gui.hpp"

cs_insn *insn;

// Keep track of backtrace, where we are in the program
AddressStack backtrace;
CliFlags flags;
bool runCliThisTick = false;
bool started = false;

void printInstructions(int j)
{
    int symbolI = hasSymbol(insn[j].address);

    if (symbolI != -1)
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
        printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
               insn[j].op_str);
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
    if (instructionsRun % 1000 == 0 && !started)
    {
        char cmd[100];
        snprintf(cmd, 100, "cat /proc/%d/maps | grep \"libc\" ", child);
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
    }
    return 0;
}

size_t disassemble(pid_t child, struct user_regs_struct *regs, csh *handle, int *status)
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

            size_t count = disassemble(child, &regs, &handle, &status);
            if (count < 0)
                break;

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
                    continue;
                }

                printInstructions(0);
                handleBacktrace(0);                

                while (!moveOn())
                {
                    if (runFlags(child) == -1) break;
                }

                cs_free(insn, count);
            }
            else
                printf("\tERROR: Failed to disassemble given code!\n");
        }

        cs_close(&handle);
    }

    backtrace.printStack();
    // Wait until the child process finishes.
    waitpid(child, &status, 0);
    std::cout << "Child finished execution." << std::endl;

    return 0;
}
