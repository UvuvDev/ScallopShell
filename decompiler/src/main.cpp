#include "main.hpp"
#include "csv.hpp"

int main() {

    std::vector<instructionData> insns;

    std::filesystem::path branchlogPath = std::filesystem::temp_directory_path() / "branchlog.csv";

    std::ifstream branchlog(branchlogPath);
    std::string csvLine;
    while (std::getline(branchlog, csvLine)) {
        insns.emplace_back(instructionData());
        parseLine(csvLine, insns.back());
    }

    for (auto i : insns) {
        std::cout << (void*)i.pc << " | " << i.disassembly << std::endl; 
    }
    
    return 0;
}