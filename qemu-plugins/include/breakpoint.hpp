#pragma once
#include "main.hpp"


/**
 * Add a breakpoint to the specified address. 
 * @param address Address to break at
 */
int addBreakpoint(uint64_t address);

/**
 * Run a specific function when breakpoint is reached
 * @param breakpoint the breakpoint ID
 * @param func Function to be run
 */
int runFunctionAtBreakpoint(int breakpoint, std::function<int()> func);

/**
 * Run a specific Python script when breakpoint is reached
 * @param breakpoint the breakpoint ID
 * @param scriptPath Script to be run's filepath
 */
int runFunctionAtBreakpoint(int breakpoint, std::string scriptPath);

