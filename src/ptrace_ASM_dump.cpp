#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <memory.h>
#include <fstream>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "capstone/capstone.h"

#include "asm_dump.hpp"


int main(int argc, char *argv[])
{

    pid_t child = fork();

    // Make a string with "./" prefixed
    char *filePathDotSlash = (char *)malloc(strlen(argv[1]) * sizeof(char) + 2);
    filePathDotSlash[0] = '.';
    filePathDotSlash[1] = '/';

    for (int i = 0; i < strlen(argv[1]); i++)
        filePathDotSlash[i + 2] = argv[1][i];
    // ==================================

    // Display read me
    startupMsg();

    std::cout << "Ready... ? " << "\n\n";

    getchar();

    // If child process...
    if (child == 0)
    {
        // Child process: allow the parent to trace us.
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
        {
            perror("ptrace(PTRACE_TRACEME)");
            exit(1);
        }

        // Replace the process with a new one (the user argument)
        execl(filePathDotSlash, argv[1], nullptr);

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

    free(filePathDotSlash);

    return 0;
}