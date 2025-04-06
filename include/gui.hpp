#include "core.hpp"

enum class CliFlags {
    def = 0,
    contin = 1,
    printBack = 2,
    ni = 3,
    breakpoint = 4,
    lay = 5
};

int Cli(CliFlags* flags);
void spinner();