#include "debug.hpp"
#include "filesystem"

std::filesystem::path debugPath = std::filesystem::temp_directory_path() / "DEBUG_LOG.txt";
FILE* debugOut = fopen(debugPath.c_str(), "w+");

void OUT_TO_FILE(std::string debug) {
    fprintf(debugOut, "%s", debug.c_str());
    fflush(debugOut);
}


void OUT_TO_FILE(const char* debug) {
    fprintf(debugOut, "%s", debug);
    fflush(debugOut);

}