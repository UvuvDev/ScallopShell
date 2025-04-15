#include "gui.hpp"
#include "asm_dump.hpp"

ExamineFlags xFlags;
int bytesToExamine = 0;

int Cli(CliFlags *flags)
{

    char cmd[100];
    printf(" > ");
    int ch;

    fgets(cmd, 100, stdin);
    clearLine();

    if (!strncmp(cmd, "\n", 1))
    {
        return 2;
    }
    if (!strncmp(cmd, "back", 4))
    {
        *flags = CliFlags::printBack;
        return 1;
    }
    if (!strncmp(cmd, "ni", 2))
    {
        *flags = CliFlags::ni;
        return 1;
    }
    if (!strncmp(cmd, "reg", 3))
    {
        *flags = CliFlags::regV;
        return 1;
    }
    if (!strncmp(cmd, "x", 1))
    {
        *flags = CliFlags::examine;
        xFlags = ExamineFlags::g;

        char flag;

        if (sscanf(&cmd[1], "/%d%c", &bytesToExamine, &flag) != -1)
        {

            switch (flag)
            {
            case 'g':
                xFlags = ExamineFlags::g;
                break;
            case 'w':
                xFlags = ExamineFlags::w;
                break;
            case 'h':
                xFlags = ExamineFlags::h;
                break;
            case 'b':
                xFlags = ExamineFlags::b;
                break;
            }

        }

        return 1;
    }
    if (!strncmp(cmd, "flag", 4))
    {
        *flags = CliFlags::pFlags;
        return 1;
    }
    if (!strncmp(cmd, "b", 1))
    {
        *flags = CliFlags::breakpoint;
        return 1;
    }
    if (!strncmp(cmd, "clear", 5))
    {
        *flags = CliFlags::clear;
        return 1;
    }
    if (!strncmp(cmd, "c", 1))
    {
        *flags = CliFlags::contin;
        return 1;
    }
    if (!strncmp(cmd, "info", 4))
    {
        *flags = CliFlags::info;
        return 1;
    }
    if (!strncmp(cmd, "lay", 3))
    {
        *flags = CliFlags::lay;
        return 1;
    }
    if (!strncmp(cmd, "starti", 6))
    {
        *flags = CliFlags::starti;
        return 1;
    }
    if (!strncmp(cmd, "q", 1))
    {
        printf("Exiting Scallop Shell....\n");
        exit(1);
    }

    return 0;
}

void spinner()
{

    static int x = 0;

    static constexpr int delay = 10000;

    switch (x % (4 * delay))
    {
    case 0:
        printf("\b|");
        fflush(stdout);
        break;
    case 1 * delay:
        printf("\b/");
        fflush(stdout);
        break;
    case 2 * delay:
        printf("\b-");
        fflush(stdout);
        break;
    case 3 * delay:
        printf("\b\\");
        fflush(stdout);
        break;
    default:
        break;
    }
    x++;
}

void clearLine()
{
    // Move the cursor up one line and clear that line:
    printf("\033[1A"); // Move up one line
    printf("\033[K");  // Clear from cursor to end of line
}

void printMemMap(int index)
{

    if (memMaps.at(index).canRun())
    {

        // If its the top address print the header
        if (insn[0].address == memMaps.at(index).bottomAddr)
            std::cout << BOLD_GREEN << "\n  #--------" << memMaps.at(index).desc << "--------#\n\n"
                      << RESET;

        // Print the instruction address, instruction and arguments
        printf("\t%s0x%" PRIx64 ":\t%s\t\t%s\n%s", GREEN, insn[0].address, insn[0].mnemonic,
               insn[0].op_str, RESET);

        // If its the bottom addr print the footer
        if (insn[0].address == memMaps.at(index).topAddr)
        {
            memMaps.at(index).run++;
            std::cout << BOLD_GREEN << "\n  #-------- end of " << memMaps.at(index).desc << "--------#\n\n"
                      << RESET;
        }
    }
}

void printBreak(int symbolI)
{

    // If there's a valid symbol table entry
    if (symbolI != -1)
    {
        // Print the modified instruction with symbols
        std::cout << BOLD_BLUE << "  " << symbolTable.at(symbolI).getAddr() << ": " << insn[0].mnemonic << "\t\t" << insn[0].op_str << " |\t<- " << symbolTable.at(symbolI).getDesc() << RESET << "\n";
        Cli(&flags);
        runCliThisTick = true;
    }
    else
    {
        // Check if there's an instruction break
        if (hasInstrucBreak(insn[0].mnemonic) == 1)
        {
            std::cout << BOLD_MAGENTA << "  " << (uint64_t *)insn[0].address << ": " << insn[0].mnemonic << "\t\t" << insn[0].op_str << RESET << "\n";
            Cli(&flags);
            runCliThisTick = true;
            return;
        }
    }
}

void printSymbol(int symbolI)
{
    // Print the modified instruction with symbols
    std::cout << BOLD_MAGENTA << "  " << symbolTable.at(symbolI).getAddr() << ": " << insn[0].mnemonic << "\t\t" << insn[0].op_str << " |\t<- " << symbolTable.at(symbolI).getDesc() << RESET << "\n";
}

void printBasic()
{
    // Print the instruction address, instruction and arguments
    std::cout << YELLOW << (uint64_t *)insn[0].address << ":\t" << BLUE
              << insn[0].mnemonic << "\t\t" << MAGENTA << insn[0].op_str << "\n"
              << RESET;
}

void printInstructions()
{
    int symbolI = hasSymbol(insn[0].address);
    int mapI = hasLoopSymbol(insn[0].address);

    if (mapI != -1)
    {
        printMemMap(mapI);
    }

    else if (symbolI != -1)
    {
        // Check if the symbol table has any matches
        if (symbolTable.at(symbolI).getType() == 'b')
        {
            printBreak(symbolI);
        }
        else if (symbolTable.at(symbolI).getType() == 's')
        {
            printSymbol(symbolI);
        }
    }
    else
    {

        printBreak(symbolI);
        printBasic();
    }
}

void printEFlags(uint64_t eflags)
{
    // Only the lower 32 bits of EFLAGS are meaningful.
    printf(BOLD_AMBER " SET FLAGS - ");

    if (eflags & (1ULL << 0))
        printf("CF "); // Carry Flag
    if (eflags & (1ULL << 2))
        printf("PF "); // Parity Flag
    if (eflags & (1ULL << 4))
        printf("AF "); // Auxiliary carry flag
    if (eflags & (1ULL << 6))
        printf("ZF "); // Zero Flag
    if (eflags & (1ULL << 7))
        printf("SF "); // Sign Flag
    if (eflags & (1ULL << 8))
        printf("TF "); // Trap Flag
    if (eflags & (1ULL << 9))
        printf("IF "); // Interrupt Enable Flag
    if (eflags & (1ULL << 10))
        printf("DF "); // Direction Flag
    if (eflags & (1ULL << 11))
        printf("OF "); // Overflow Flag

    printf(RESET "\n");
}

void printRegVerbose()
{

    // Print a decorative line header
    printf(BOLD_BLACK "#------------------------------------------------------------- REGISTERS ---------------------------------------------------------#\n" RESET);

    // Row 1
    printf(BOLD_GREEN "%-8s = 0x%016llx   " RESET, " $RAX", regs.rax);
    printf(BOLD_CYAN "%-8s = 0x%016llx   " RESET, "$RBX", regs.rbx);
    printf(BOLD_BLUE "%-8s = 0x%016llx   " RESET, "$RCX", regs.rcx);
    printf(BOLD_MAGENTA "%-8s = 0x%016llx\n" RESET, "$RDX", regs.rdx);

    // Row 2
    printf(BOLD_GREEN "%-8s = 0x%016llx   " RESET, " $RDI", regs.rdi);
    printf(BOLD_CYAN "%-8s = 0x%016llx   " RESET, "$RSI", regs.rsi);
    printf(BOLD_BLUE "%-8s = 0x%016llx   " RESET, "$RBP", regs.rbp);
    printf(BOLD_MAGENTA "%-8s = 0x%016llx\n" RESET, "$RSP", regs.rsp);

    // Row 3
    printf(BOLD_GREEN "%-8s = 0x%016llx   " RESET, " $RIP", regs.rip);
    printf(BOLD_CYAN "%-8s = 0x%016llx   " RESET, "$R8", regs.r8);
    printf(BOLD_BLUE "%-8s = 0x%016llx   " RESET, "$R9", regs.r9);
    printf(BOLD_MAGENTA "%-8s = 0x%016llx\n" RESET, "$R10", regs.r10);

    // Row 4
    printf(BOLD_GREEN "%-8s = 0x%016llx   " RESET, " $R11", regs.r11);
    printf(BOLD_CYAN "%-8s = 0x%016llx   " RESET, "$R12", regs.r12);
    printf(BOLD_BLUE "%-8s = 0x%016llx   " RESET, "$R13", regs.r13);
    printf(BOLD_MAGENTA "%-8s = 0x%016llx\n" RESET, "$R14", regs.r14);

    // Row 5
    printf(BOLD_GREEN "%-8s = 0x%016llx   " RESET, " $R15", regs.r15);
    printf(BOLD_CYAN "%-8s = 0x%016llx\n" RESET, "$EFLAGS", regs.eflags);

    printEFlags(regs.eflags);

    // Print a decorative line footer
    printf(BOLD_BLACK "#---------------------------------------------------------------------------------------------------------------------------------#\n" RESET);
}

void handleBacktrace()
{
    if (!strncmp(insn[0].mnemonic, "ret", 3))
    {
        backtrace.pop();
    }
    if (!strncmp(insn[0].mnemonic, "call", 4))
    {
        backtrace.push(insn[0].address);
    }
}

bool moveOn()
{
    return (flags == CliFlags::contin);
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
    case CliFlags::regV:
        printRegVerbose();
        Cli(&flags);
        break;
    case CliFlags::pFlags:
        printEFlags(regs.eflags);
        Cli(&flags);
        break;
    case CliFlags::examine:

        uint64_t address = 0;
        printf(BOLD_BLUE "\tEnter address in hex: " RESET);

        if (scanf("%llx", &address) != 1)
        {
            printf(RED "ERROR: Invalid input for address.\n\n\n" RESET);
            Cli(&flags);
            break;
        }

        if (address == 0)
        {
            printf(RED "ERROR: Invalid input for address.\n\n\n" RESET);
            Cli(&flags);
            break;
        }

        // xFlags is assumed to be a variable holding number of bytes to read (1,2,4, or 8).
        // For demonstration, let’s assume xFlags is defined, or hardcode it:
        int bytesToRead = (int)xFlags * bytesToExamine; // Change this as needed, or set from xFlags.
        int offset = 0;

        printf(BOLD_CYAN  "\n\t\tData at 0x%llx: ", address);

        while (offset < bytesToRead)
        {
            errno = 0; // Clear errno before ptrace call.
            // Read one word (typically 8 bytes) from the target's address space.
            long data = ptrace(PTRACE_PEEKDATA, child, (void *)(address + offset), 0);
            if (data == -1 && errno != 0)
            {
                perror("ptrace(PTRACE_PEEKDATA) failed" RESET);
                Cli(&flags);
                break;
            }

            // Determine how many bytes to print from this word.
            int bytesThisWord = sizeof(long);
            if (offset + bytesThisWord > bytesToRead)
                bytesThisWord = bytesToRead - offset;

            // Print each byte from the word in little-endian order.
            for (int j = 0; j < bytesThisWord; j++)
            {
                uint8_t byte = (data >> (8 * j)) & 0xFF;
                printf("%02x ", byte);
            }

            offset += sizeof(long);
        }
        printf(RESET "\n");

        while (getchar() != '\n');
        
        Cli(&flags);
        break;
    }

    return 0;
}