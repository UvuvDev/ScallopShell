#include "asm_dump.hpp"
#include "datastructs.hpp"

int assemblyDump(pid_t child)
{

    // Parent process: wait for the child to stop.
    int status;
    struct user_regs_struct regs;

    // Keep track of backtrace, where we are in the program
    AddressStack backtrace;

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

        int instructionsRun = 0;

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
                    printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic,
                           insn[j].op_str);

                    if (!strncmp(insn[j].mnemonic, "ret", 3)) {
                        backtrace.pop();
                    }
                    if (!strncmp(insn[j].mnemonic, "call", 4)) {
                        backtrace.push(insn[j].address);
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
