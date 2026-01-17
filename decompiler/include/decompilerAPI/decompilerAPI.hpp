#include "string"
#include "filesystem"

class DecompilerAPI {
private:


public:

    static int runDecompiler(std::filesystem::path ghidraHeadlessPath, std::filesystem::path binaryPath);

};