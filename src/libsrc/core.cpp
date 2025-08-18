#include "core.hpp"

std::vector<MemMap *> ignoredFunctions;
std::vector<Symbol> symbolTable;
std::vector<MemMap *> memMaps;

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

    std::cout << "Scallop Shell - Disassembler and Debugger for self modifying / polymorphic binaries.\n";
    std::cout << "  - Bradley Fernandez / Uvuv\n\n\n";
}

char *makeFilepath(char *argv)
{
    // Make a string with "./" prefixed
    char *filePathDotSlash = (char *)malloc(strlen(argv) * sizeof(char) + 2);
    filePathDotSlash[0] = '.';
    filePathDotSlash[1] = '/';

    for (int i = 0; i < strlen(argv); i++)
        filePathDotSlash[i + 2] = argv[i];

    return filePathDotSlash;
}

int hasSymbol(uint64_t address)
{

    for (int i = 0; i < symbolTable.size(); i++)
    {
        if ((uint64_t)symbolTable.at(i).getAddr() == address)
            return i;
    }
    return -1;
}

/**
 * Checks if the address you give is in any of the given memory map ranges, and if so, what index its in
 */
int hasLoopSymbol(uint64_t address)
{

    for (int i = 0; i < memMaps.size(); i++)
    {
        if (memMaps.at(i)->isInRange(address))
            return i;
    }
    return -1;
}

int hasInstrucBreak(char *instruction)
{

    for (int i = 0; i < symbolTable.size(); i++)
    {
        if (!strcmp(symbolTable.at(i).getDesc().c_str(), instruction))
            return 1;
    }
    return -1;
}

std::vector<std::string> findInternalLibs()
{

    std::ifstream libconfig("config/libraryconfig.txt");
    std::vector<std::string> libs;
    std::string tempString;

    // Check if libconfig exists
    if (!libconfig.is_open())
    {
        std::cout << BOLD_RED << "ERROR! YOU NEED A LIBRARYCONFIG.TXT FILE. ADD FILE AND RESTART" << RESET << std::endl;
        exit(1);
    }

    // Save each line of config
    while (std::getline(libconfig, tempString))
    {
        libs.emplace_back(tempString);
    }

    return libs;
}

void conditionallyUpdateMaps(std::vector<MemMap *> *_map, std::string desc, uint64_t lower, uint64_t upper, char type)
{

    for (auto map : *_map)
    {
        // If it's in the map vector already, add to the address vector on the map
        if (map->desc.compare(desc) == 0)
        {
            map->addMemoryRange(lower, upper); // Add memory mappings
            return;
        }
    }

    // Otherwise, add a new map
    _map->emplace_back(new MemMap(lower, upper, desc, type, 0));
}

void checkLoadedMappings(std::vector<std::string> libs)
{

    // Open process memory map
    std::string mapPath = "/proc/" + std::to_string(child) + "/maps";
    FILE *procMaps = fopen(mapPath.c_str(), "r");
    if (!procMaps)
    {
        std::cout << BOLD_RED << "Failure reading proc/maps! Exiting." << RESET << std::endl;
        exit(1);
        return;
    }

    // Parse proc maps and get the current libraries and locations in mem
    char mapBuffer[1024];
    uint64_t lower, upper;

    // For every map inside /proc/maps
    while (fgets(mapBuffer, sizeof(mapBuffer), procMaps)) {
        unsigned long lower = 0, upper = 0, offset = 0, inode = 0;
        unsigned int maj = 0, min = 0;
        char perms[5] = {};
        char path[1024] = {};            

        // /proc/<pid>/maps format:
        // address          perms offset  dev     inode   pathname?
        // 00400000-0040b000 r-xp 00000000 08:02  131073  /bin/cat
        int dataRead = sscanf(mapBuffer,
                       "%lx-%lx %4s %lx %x:%x %lu %1023s",
                       &lower, &upper, perms, &offset, &maj, &min, &inode, path);

        std::string filename = path;

        if (dataRead == 2) {
            continue;
        }
        
        // Iterate through the process maps and add the files seen into currentProcessMem
        for (auto library : libs)
        {
        
            // One of those weird allocated memory blocks
            if (filename[0] == '[') {
                conditionallyUpdateMaps(&ignoredFunctions, filename, lower, upper, 'i'); // Add memmaps from proc maps to a vector
            }

            // If the config'd line is a directory
            if (library.back() == '/')
            {
                //std::cout << "fifeowipfuewpoifueqpofywe87ry3297u32fj327f82ufew7f8ewuf78weqfwqe" << std::endl;
                // If it's in the config file directory, add to the map
                if (filename.compare(0, library.size(), library, 0, library.size()) == 0)
                {                    
                    conditionallyUpdateMaps(&ignoredFunctions, filename, lower, upper, 'i'); // Add memmaps from proc maps to a vector
                    break;
                }
                else
                {
                    continue;
                }
            }
            else
            {
                //std::cout << "1ry329e8rte8fweuifeduifqwripufwqfeqw" << std::endl;
                // If it's in the config file directory, add to the map
                if (filename.compare(library) == 0)
                {
                    conditionallyUpdateMaps(&ignoredFunctions, filename, lower, upper, 'i'); // Add memmaps from proc maps to a vector
                    break;
                }
                else
                {
                    continue;
                }
            }
        }
    }

    fclose(procMaps);
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
            if (printGLIBC)
            {
                std::cout << BOLD_BLUE << " In GLIBC at " << symbolTable.at(i).getDesc()
                          << RESET
                          << "\n";
            }
        }
    }
}

int watch_map_files(pid_t pid)
{
    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0)
        return -1;
    std::string dir = "/proc/" + std::to_string(pid) + "/map_files";
    int wd = inotify_add_watch(fd, dir.c_str(), IN_CREATE | IN_DELETE | IN_DELETE_SELF);
    if (wd < 0)
    {
        close(fd);
        return -1;
    }
    return fd; // use poll/epoll on fd; on event → read maps & parse
}

int map_files_changed(int inotify_fd)
{
    struct pollfd pfd{inotify_fd, POLLIN, 0};
    int pr = poll(&pfd, 1, 0); // non-blocking check
    if (pr < 0)
        return -1; // poll error
    if (pr == 0)
        return 0; // nothing to read

    bool changed = false;
    char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
    for (;;)
    {
        ssize_t n = read(inotify_fd, buf, sizeof(buf));
        if (n < 0)
        {
            if (errno == EAGAIN)
                break; // drained
            return -1;
        }
        if (n == 0)
            break;

        const char *ptr = buf;
        while (ptr < buf + n)
        {
            const struct inotify_event *ev = reinterpret_cast<const struct inotify_event *>(ptr);
            if (ev->mask & (IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO))
            {
                changed = true;
            }
            if (ev->mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT |
                            IN_IGNORED | IN_Q_OVERFLOW))
            {
                changed = true;
            }
            ptr += sizeof(struct inotify_event) + ev->len;
        }
    }
    return changed ? 1 : 0;
}