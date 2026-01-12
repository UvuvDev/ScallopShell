#include "main.hpp"
#include "csv.hpp"
#include "filter.hpp"
#include "unordered_map"

int main() {

    std::vector<instructionData> insns;

    std::filesystem::path branchlogPath = std::filesystem::temp_directory_path() / "branchlog.csv";

    std::ifstream branchlog(branchlogPath);
    std::string csvLine;
    while (std::getline(branchlog, csvLine)) {
        insns.emplace_back(instructionData());
        parseLine(csvLine, insns.back());
    }

    std::unordered_map<uint64_t, int> insnLooping;

    for (auto i : insns) {
        std::cout << (void*)i.pc << " | " << i.disassembly << std::endl;
        
        if (shouldBranch(i)) {
            std::cout << "  |  " << std::endl;
            std::cout << "  |  " << std::endl;
            insnLooping[i.pc] += 1;
        }
    
    }
    
    return 0;
}