#include "capstone/capstone.h"
#include "loop.hpp"
#include "linux/elf.h"

pid_t child;

/**
 *  Scallop Shell
 *      Bradley Fernandez 2025
 *
 * Debug obfuscated programs with ease. See README.md.
 *
 *
 */

void initializeSymbols(char *argv[])
{

    system("clear");

    char *symbolsFilepath = makeFilepath(argv[2]);

    FILE *symbolFile = fopen(argv[2], "r");

    uint64_t addr;
    char desc[30];
    SymbolType type;

    while (fscanf(symbolFile, "%lx %s %c", &addr, desc, &type) == 3)
    {
        switch (type)
        {
        case 's':
            symbolTable.emplace_back(Symbol(addr, desc, type));
            break;
        case 'b':
            symbolTable.emplace_back(Symbol(addr, desc, type));
            break;
        case 'l':
            uint64_t topAddrLoop;
            int maxrun;
            fscanf(symbolFile, "%lx %d", &topAddrLoop, &maxrun);
            if (addr < topAddrLoop)
                memMaps.emplace_back(addr, topAddrLoop, desc, type, maxrun);
            else
                memMaps.emplace_back(topAddrLoop, addr, desc, type, maxrun);
            break;
        case 'm':
            uint64_t topAddrMap;
            fscanf(symbolFile, "%lx", &topAddrMap);
            if (addr < topAddrMap)
                memMaps.emplace_back(addr, topAddrMap, desc, type, -1);
            else
                memMaps.emplace_back(topAddrMap, addr, desc, type, -1);
            break;
        }
    }

    fclose(symbolFile);
}

int main(int argc, char *argv[])
{

    // Make the filepath for the program to debug
    char *programFilepath = makeFilepath(argv[1]);

    initializeSymbols(argv);

    // Display read me, wait for user confirmation to start
    startupMsg();
    std::cout << "Ready... ? " << "\n\n";
    getchar();

    /* When all pre processing is done, fork. */
    child = fork();
    // If child process...
    if (child == 0)
    {
        // Child process: allow the parent to trace us.
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
        {
            perror("ptrace(PTRACE_TRACEME)");
            exit(1);
        }

        // Disable ASLR by setting the ADDR_NO_RANDOMIZE flag.
        unsigned long pers = personality(0xffffffff);
        personality(pers | ADDR_NO_RANDOMIZE);

        // Replace the process with a new one (the user argument)
        execl(programFilepath, argv[1], nullptr);

        perror("execl"); // Only reached if execl fails
        exit(1);
    }
    // If parent process...
    else if (child > 0)
    {

        assemblyDump(child);
    }
    else
    {
        perror("fork");
        return 1;
    }

    free(programFilepath);

    return 0;
}