#include "asm_dump.hpp"
#include "datastructs.hpp"

cs_insn *insn;

// Keep track of backtrace, where we are in the program
AddressStack backtrace;

void printInstructions(SymbolTable &symbolTable, int j)
{
    int symbolI = hasSymbol(symbolTable, insn[j].address);

    if (symbolI != -1)
    {
        // Print the modified instruction with symbols
        std::cout << BOLD_MAGENTA << "  " << symbolTable.at(symbolI).getAddr() << ": " << insn[j].mnemonic << "\t\t" << insn[j].op_str << " |\t<- " << symbolTable.at(symbolI).getDesc() << RESET << "\n";
    }
    else
    {
        // Print the instruction address, instruction and arguments
        printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
               insn[j].op_str);
    }
}

void handleBacktrace(SymbolTable &symbolTable, int j)
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

int assemblyDump(pid_t child, std::vector<Symbol> &symbolTable)
{

    std::vector<std::pair<uint64_t, uint64_t>> ignoredFunctions;
    char cmd[50];
    snprintf(cmd, 50, "cat /proc/%d/maps | grep \"libc\" ", child); 
    FILE* map = popen(cmd, "r");

    
    {
        uint64_t lowerLibCTemp;
        uint64_t upperLibCTemp;
        char junk[100];
        while (fscanf(map, "%lx-%lx %*s %*s %*s %*s %*s", &lowerLibCTemp, &upperLibCTemp) == 7)
            ignoredFunctions.emplace_back(std::make_pair(lowerLibCTemp, upperLibCTemp));
    }
    
    for (const auto& range : ignoredFunctions) {
        printf("Range: 0x%lx - 0x%lx\n", range.first, range.second);
    }
    
    fclose(map);

    // Parent process: wait for the child to stop.
    int status;
    struct user_regs_struct regs;

    csh handle;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        return -1;

    waitpid(child, &status, 0); // Stop the child process until we start it again

    if (WIFSTOPPED(status))
    {
        std::cout << "Child stopped, now continuing execution." << std::endl;
        // Resume the child process.

        printf("child pid = %d\n", child);
        getchar();

        int instructionsRun = 0;
        bool inLibC = 0;

        uint64_t lastBack = backtrace.top();

        while (true)
        {

            if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) == -1)
            {
                perror("ptrace(PTRACE_SINGLESTEP)");
                break;
            }

            waitpid(child, &status, 0);

            if (WIFEXITED(status))
            {
                printf("Program exited, breaking\n");
                break;
            }

            if (ptrace(PTRACE_GETREGS, child, nullptr, &regs) == -1)
            {
                perror("ptrace(PTRACE_GETREGS)");
                break;
            }

            // If 3 instructions havent been run, continue
            //      - every instruction is shown only once
            instructionsRun++;
            if (instructionsRun % 3 != 0)
                continue;

            // Set the opcode
            unsigned long firstHalf = ptrace(PTRACE_PEEKDATA, child, regs.rip, nullptr);
            unsigned long secondHalf = ptrace(PTRACE_PEEKDATA, child, regs.rip + 8, nullptr);
            uint8_t opcode[16];
            assignOpcode(opcode, firstHalf, secondHalf);

            // Disassemble the opcode (max 16 bytes), telling it its at the addr $RIP
            count = cs_disasm(handle, opcode, 16, regs.rip, 0, &insn);

            // If there was any instructions:
            if (count > 0)
            {
                size_t j;
                for (j = 0; j < count; j++)
                {
                    printInstructions(symbolTable, j);
                    handleBacktrace(symbolTable, j);
                    inLibC = isLibC(ignoredFunctions, regs.rip);

                    if (inLibC)
                    {
                        std::cout << BOLD_RED;
                    }
                    else
                    {
                        std::cout << BOLD_CYAN;
                    }
                }

                cs_free(insn, count);
            }
            else
                printf("ERROR: Failed to disassemble given code!\n");
        }

        cs_close(&handle);
    }

    backtrace.printStack();
    // Wait until the child process finishes.
    waitpid(child, &status, 0);
    std::cout << "Child finished execution." << std::endl;

    return 0;
}
