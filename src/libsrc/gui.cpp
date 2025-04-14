#include "gui.hpp"
#include "asm_dump.hpp"

int Cli(CliFlags* flags)
{

    char cmd[20];
    printf(" > ");
    int ch;

    fgets(cmd, 20, stdin);
    clearLine();

    if (!strncmp(cmd, "\n", 1)) {
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

    switch (x % (4*delay))
    {
    case 0:
        printf("\b|");
        fflush(stdout);
        break;
    case 1*delay:
        printf("\b/");
        fflush(stdout);
        break;
    case 2*delay:
        printf("\b-");
        fflush(stdout);
        break;
    case 3*delay:
        printf("\b\\");
        fflush(stdout);
        break;
    default:
        break;
    }
    x++;
}

void clearLine() {
    // Move the cursor up one line and clear that line:
    printf("\033[1A");  // Move up one line
    printf("\033[K");   // Clear from cursor to end of line
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

void printBasic() {
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
    }

    return 0;
}