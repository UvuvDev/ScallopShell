#include "decompilerAPI/decompilerAPI.hpp"
#include "decompilerAPI/ghidra.hpp"

int DecompilerAPI::runDecompiler(std::filesystem::path ghidraHeadlessPath, std::filesystem::path binaryPath) {

    std::string projectName = "ScallopAnalysis";
    std::string projectSubdir = "CTF";

    return runHeadless(ghidraHeadlessPath, binaryPath, projectName, projectSubdir);

}