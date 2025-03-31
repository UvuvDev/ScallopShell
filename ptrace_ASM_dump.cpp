#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <memory.h>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "capstone/capstone.h"

#include "ev/eventhandler.hpp"

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
    else if (child > 0)
    {
        // Parent process: wait for the child to stop.
        int status;
        struct user_regs_struct regs;

        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return -1;

        waitpid(child, &status, 0); // Stop the child process until we start it again

        if (WIFSTOPPED(status))
        {
            std::cout << "Child stopped, now continuing execution." << std::endl;
            // Resume the child process.

            while (true)
            {

                if (ptrace(PTRACE_SINGLESTEP, child, nullptr, nullptr) == -1)
                {
                    perror("ptrace(PTRACE_SINGLESTEP)");
                    break;
                }

                waitpid(child, &status, 0);

                if (ptrace(PTRACE_GETREGS, child, nullptr, &regs) == -1)
                {
                    perror("ptrace(PTRACE_GETREGS)");
                    break;
                }

                std::cout << "RIP = 0x" << regs.rip << std::endl;
                
                unsigned long firstHalf = ptrace(PTRACE_PEEKDATA, child, regs.rip, nullptr);
                unsigned long secondHalf = ptrace(PTRACE_PEEKDATA, child, regs.rip + 8, nullptr);

                // Opcode array first half
                uint8_t opcode[16];                    
                opcode[0] = (firstHalf & 0x00000000000000FF);
                opcode[1] = (firstHalf & 0x000000000000FF00) >> 0x8;
                opcode[2] = (firstHalf & 0x0000000000FF0000) >> 0x10;
                opcode[3] = (firstHalf & 0x00000000FF000000) >> 0x18;
                opcode[4] = (firstHalf & 0x000000FF00000000) >> 0x20;
                opcode[5] = (firstHalf & 0x0000FF0000000000) >> 0x28;
                opcode[6] = (firstHalf & 0x00FF000000000000) >> 0x30;
                opcode[7] = (firstHalf & 0xFF00000000000000) >> 0x38;
                
                // Opcode array second half
                opcode[8] = (secondHalf & 0x00000000000000FF);
                opcode[9] = (secondHalf & 0x000000000000FF00) >> 0x8;
                opcode[10] = (secondHalf & 0x0000000000FF0000) >> 0x10;
                opcode[11] = (secondHalf & 0x00000000FF000000) >> 0x18;
                opcode[12] = (secondHalf & 0x000000FF00000000) >> 0x20;
                opcode[13] = (secondHalf & 0x0000FF0000000000) >> 0x28;
                opcode[14] = (secondHalf & 0x00FF000000000000) >> 0x30;
                opcode[15] = (secondHalf & 0xFF00000000000000) >> 0x38;

                count = cs_disasm(handle, opcode, 1*16 - 1, 0x1000, 0, &insn);

                if (count > 0)
                {
                    size_t j;
                    for (j = 0; j < count; j++)
                    {
                        printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                               insn[j].op_str);
                    }

                    cs_free(insn, count);
                }
                else
                    printf("ERROR: Failed to disassemble given code!\n");

                cs_close(&handle);
            }
        }

        // Wait until the child process finishes.
        waitpid(child, &status, 0);
        std::cout << "Child finished execution." << std::endl;
    }
    else
    {
        perror("fork");
        return 1;
    }

    free(filePathDotSlash);

    return 0;
}