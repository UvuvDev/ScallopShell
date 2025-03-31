#pragma once

#include <unistd.h>
#include <cstdlib>
#include <string.h>
#include <memory.h>
#include <fstream>
#include <iostream>

#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#include "capstone/capstone.h"
#include "eventhandler.hpp"

void assignOpcode(uint8_t *opcode, int firstHalf, int secondHalf);
void startupMsg();