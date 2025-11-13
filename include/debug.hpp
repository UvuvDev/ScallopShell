#pragma once
#include <string>

extern FILE* debugOut;

void OUT_TO_FILE(std::string debug);


void OUT_TO_FILE(const char* debug);