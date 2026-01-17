#include "main.hpp"
#include "csv.hpp"
#include "filter.hpp"
#include "unordered_map"
#include "decompilerAPI.hpp"
#include <cstdlib>

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

    std::cout << "Got lines " << std::endl;

    std::unordered_map<uint64_t, int> insnLooping;
    std::vector<uint8_t> memoryImageBytes;
    
    uint64_t base = 0;
    uint64_t entry = 0;
    auto image = buildMemoryImage(insns, base, entry, 0xCC);

    std::cout << "Built memory image" << std::endl;
    if (!image.empty()) {
        std::filesystem::path outPath = std::filesystem::temp_directory_path() / "scallop";
        if (writeElfX64LE(outPath, image, base, entry)) {
            std::cout << "Wrote ELF to " << outPath << " (base=0x"
                      << std::hex << base << ", entry=0x" << entry << ")" << std::dec << std::endl;

            const int rc = DecompilerAPI::runDecompiler(std::filesystem::path(std::getenv("HOME")) / "Applications" / "ghidra_11.4.1_PUBLIC" / "support" / "analyzeHeadless", outPath);
            if (rc != 0) {
                std::cerr << "analyzeHeadless exited with code " << rc << std::endl;
            }
        } else {
            std::cerr << "Failed to write ELF to " << outPath << std::endl;
        }
    }

    return 0;
}
