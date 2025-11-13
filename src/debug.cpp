#include "debug.hpp"

FILE* debugOut = fopen("DEBUG_LOG.txt", "w+");

void OUT_TO_FILE(std::string debug) {
    fprintf(debugOut, "%s", debug.c_str());
    fflush(debugOut);

}


void OUT_TO_FILE(const char* debug) {
    fprintf(debugOut, "%s", debug);
    fflush(debugOut);

}