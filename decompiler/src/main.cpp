#include "main.hpp"
#include "csv.hpp"
#include "filter.hpp"
#include "unordered_map"
#include <cstdlib>

namespace {
const char* kGhidraHeadlessPath =
    "/home/bradley/Applications/ghidra_11.4.1_PUBLIC/support/analyzeHeadless";
const char* kProjectName = "MyProject";
const char* kProjectSubdir = "CTF";

std::filesystem::path getProjectLocation() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        return {};
    }
    return std::filesystem::path(home) / kProjectSubdir;
}

int runHeadless(const std::filesystem::path& elfPath) {
    const auto projectLoc = getProjectLocation();
    if (projectLoc.empty()) {
        std::cerr << "HOME not set; cannot locate project directory." << std::endl;
        return -1;
    }

    std::string cmd;
    cmd.reserve(512);
    cmd.append(kGhidraHeadlessPath)
        .append(" ")
        .append(projectLoc.string())
        .append(" ")
        .append(kProjectName)
        .append(" -import ")
        .append(elfPath.string())
        .append(" -overwrite");

    return std::system(cmd.c_str());
}
} // namespace

int main() {

    std::vector<instructionData> insns;

    std::filesystem::path branchlogPath = std::filesystem::temp_directory_path() / "branchlog.csv";

    std::ifstream branchlog(branchlogPath);
    std::string csvLine;
    while (std::getline(branchlog, csvLine)) {
        instructionData insn;
        if (parseLine(csvLine, insn) == 0) {
            insns.emplace_back(std::move(insn));
        }
    }

    std::unordered_map<uint64_t, int> insnLooping;
    std::vector<uint8_t> memoryImageBytes;
    
    uint64_t base = 0;
    uint64_t entry = 0;
    auto image = buildMemoryImage(insns, base, entry, 0xCC);

    if (!image.empty()) {
        std::filesystem::path outPath = std::filesystem::temp_directory_path() / "scallop.elf";
        if (writeElfX64LE(outPath, image, base, entry)) {
            std::cout << "Wrote ELF to " << outPath << " (base=0x"
                      << std::hex << base << ", entry=0x" << entry << ")" << std::dec << std::endl;
            const int rc = runHeadless(outPath);
            if (rc != 0) {
                std::cerr << "analyzeHeadless exited with code " << rc << std::endl;
            }
        } else {
            std::cerr << "Failed to write ELF to " << outPath << std::endl;
        }
    }

    return 0;
}
