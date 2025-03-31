#pragma once

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

#include "eventhandler.hpp"

/**
 * Watch memory, if memory's changed then return true.
 */
int watchMemory(pid_t child, uint64_t address, int nBytes);

/**
 * Watch register, if memory's changed then return true.
 */
int watchRegister(pid_t child, unsigned long long reg);