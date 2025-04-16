#include "core.hpp"

std::vector<std::pair<uint64_t, uint64_t>> ignoredFunctions;
std::vector<Symbol> symbolTable;
std::vector<MemMap> memMaps;

void assignOpcode(uint8_t *opcode, int firstHalf, int secondHalf)
{

    // Opcode array first half
    opcode[0] = (firstHalf & 0x00000000000000FF);
    opcode[1] = (firstHalf & 0x000000000000FF00) >> 0x8;
    opcode[2] = (firstHalf & 0x0000000000FF0000) >> 0x10;
    opcode[3] = (firstHalf & 0x00000000FF000000) >> 0x18;
    opcode[4] = (firstHalf & 0x000000FF00000000) >> 0x20;
    opcode[5] = (firstHalf & 0x0000FF0000000000) >> 0x28;
    opcode[6] = (firstHalf & 0x00FF000000000000) >> 0x30;
    opcode[7] = (firstHalf & 0xFF00000000000000) >> 0x38;

    // Opcode array second half
    opcode[8] = (secondHalf & 0x00000000000000FF);
    opcode[9] = (secondHalf & 0x000000000000FF00) >> 0x8;
    opcode[10] = (secondHalf & 0x0000000000FF0000) >> 0x10;
    opcode[11] = (secondHalf & 0x00000000FF000000) >> 0x18;
    opcode[12] = (secondHalf & 0x000000FF00000000) >> 0x20;
    opcode[13] = (secondHalf & 0x0000FF0000000000) >> 0x28;
    opcode[14] = (secondHalf & 0x00FF000000000000) >> 0x30;
    opcode[15] = (secondHalf & 0xFF00000000000000) >> 0x38;
}

void startupMsg()
{

    std::ifstream file("README.md"); // Open the file in text mode.
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open README.md" << std::endl;
        return;
    }

    std::string line;
    // Read file line by line and output it to the console.
    while (std::getline(file, line))
    {
        std::cout << line << "\n";
    }

    file.close(); // Close the file.
}

char* makeFilepath(char* argv) {
    // Make a string with "./" prefixed
    char *filePathDotSlash = (char *)malloc(strlen(argv) * sizeof(char) + 2);
    filePathDotSlash[0] = '.';
    filePathDotSlash[1] = '/';

    for (int i = 0; i < strlen(argv); i++)
        filePathDotSlash[i + 2] = argv[i];

    return filePathDotSlash;
    
}

int hasSymbol(uint64_t address) {

    for (int i = 0; i < symbolTable.size(); i++) {
        if ((uint64_t)symbolTable.at(i).getAddr() == address) return i;
    }
    return -1;

}

int hasLoopSymbol(uint64_t address) {

    for (int i = 0; i < memMaps.size(); i++) {
        if (memMaps.at(i).bottomAddr <= address && memMaps.at(i).topAddr >= address) return i;
    }
    return -1;

}

int hasInstrucBreak(char* instruction) {

    for (int i = 0; i < symbolTable.size(); i++) {
        if (!strcmp(symbolTable.at(i).getDesc().c_str(), instruction)) return 1;
    }
    return -1;

}


// Returns true if the given address is within libc.
bool isIgnored(std::vector<std::pair<uint64_t, uint64_t>> ranges, uint64_t addr) {
    
    for (auto& i : ranges) {
        if (i.first <= addr && i.second >= addr) return true;
    }
    return false;
}

int filterLinuxInit(pid_t child)
{
    char cmd[100];
    snprintf(cmd, 100, "cat /proc/%d/maps | grep \"ld-linux-x86-64.so\" ", child);
    FILE *map = popen(cmd, "r"); // Run a command that finds all GLIBC refs in /proc/##/maps

    {
        uint64_t lowerLibCTemp;
        uint64_t upperLibCTemp;
        while (fscanf(map, "%lx-%lx%*[^\n]\n", &lowerLibCTemp, &upperLibCTemp) == 2)
        {
            ignoredFunctions.emplace_back(std::make_pair(lowerLibCTemp, upperLibCTemp));
        }
    }

    fclose(map);

    return 0;
}

int filterLibC(pid_t child, int instructionsRun, bool started)
{
    // Check to see if LibC has been loaded yet
    if (instructionsRun % 100000 == 0 && !started)
    {

        /*== READ THE MEMORY MAP OF LIBC ==*/
        char cmd[100];
        snprintf(cmd, 100, "cat /proc/%d/maps | grep \"libc\" ", child);
        FILE *map = popen(cmd, "r"); // Run a command that finds all GLIBC refs in /proc/##/maps

        uint64_t lowerLibCTemp;
        uint64_t upperLibCTemp;
        uint64_t libcbase = UINT64_MAX;

        while (fscanf(map, "%lx-%lx%*[^\n]\n", &lowerLibCTemp, &upperLibCTemp) == 2)
        {
            ignoredFunctions.emplace_back(std::make_pair(lowerLibCTemp, upperLibCTemp));

            if (lowerLibCTemp < libcbase)
                libcbase = lowerLibCTemp;
        }

        pclose(map);

        /*== LOAD SYMBOL TABLE ==*/

        // Load the symbol table of LibC
        FILE *libc_symbols = popen("readelf -sW /lib/x86_64-linux-gnu/libc.so.6", "r");
        if (libc_symbols == NULL)
        {
            return 1;
        }

        uint64_t libcaddr;
        char symbolName[256]; // Make sure the array is large enough
        char line[1024];
        int header_found = 0;

        // Process output line by line.
        while (fgets(line, sizeof(line), libc_symbols) != NULL)
        {
            // Look for the header line that begins the symbol table entries.
            if (!header_found)
            {
                if (strstr(line, "Num:") != NULL)
                {
                    header_found = 1; // Now the following lines are the entries.
                }
                continue; // Skip header lines.
            }

            if (sscanf(line, " %*d: %lx %*d %*s %*s %*s %*s %[^\n]", &libcaddr, symbolName) != 2)
            {
                continue;
            }
            // printf("Address: 0x%lx, Symbol: %s\n", libcaddr, symbolName);
            // printf("%lx\n", libcbase);
            symbolTable.emplace_back(Symbol(libcbase + libcaddr, symbolName, 's'));
        }

        pclose(libc_symbols);
    }
    return 0;
}

void isInLibC(uint64_t rip)
{

    int i = hasSymbol(rip);

    if (i != -1)
    {
        if (symbolTable.at(i).getDesc().find("GLIBC") == std::string::npos &&
            symbolTable.at(i).getDesc().find("glibc") == std::string::npos &&
            symbolTable.at(i).getDesc().find("GNU") == std::string::npos)
        {
            return;
        }
        else
        {
            if (printGLIBC) {
            std::cout << BOLD_BLUE << " In GLIBC at " << symbolTable.at(i).getDesc()
                      << "\n"
                      << RESET;
            }
        }
    }
}
