#include "emulatorAPI.hpp"
#include "guihelpers.hpp"

// POSIX
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <bits/stdc++.h>

// C++
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include "debug.hpp"
#include <bit>
#include <mutex>
#include <optional>

int child_pid_ = -1;
int sock_fd_ = -1;

static constexpr const char *kMemDump = "/tmp/memdump.txt";
static constexpr const char *kRegDump = "/tmp/regdump.txt";

bool Emulator::isEmulating = false;
static std::vector<InstructionInfo> instructionInfo;
std::atomic_uint64_t Emulator::flags[MAX_VCPUS];

namespace {
struct PendingSetMem {
    uint64_t address = 0;
    int size = 0;
    std::vector<uint8_t> data;
};

std::optional<PendingSetMem> g_pending_setmem;
std::mutex g_pending_setmem_mu;
} // namespace

int socket_fd() { return sock_fd_; }
int pid() { return child_pid_; }

bool readWholeFile(const std::string &path, std::string &out)
{
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    if (!ifs)
        return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

bool writeWholeFile(const std::string &path, const std::string &contents)
{
    std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs)
        return false;
    ofs.write(contents.data(), (std::streamsize)contents.size());
    return ofs.good();
}

bool writeWholeFile(const std::string &path, const uint8_t *data, int n)
{
    if (!data || n <= 0)
        return false;

    std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs)
        return false;

    ofs.write(reinterpret_cast<const char *>(data), static_cast<std::streamsize>(n));
    return ofs.good();
}

static std::string trim(std::string s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos)
        return std::string{};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static uint64_t parse_hex(const std::string &s)
{
    std::string t = trim(s);
    if (t.empty() || t == "0" || t == "0x0")
        return 0ULL;
    const char *p = t.c_str();
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'))
        p += 2;
    char *end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    return static_cast<uint64_t>(v);
}

static std::vector<std::string> parse_csv(const std::string &line)
{
    std::vector<std::string> out;
    std::string field;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i)
    {
        char c = line[i];
        if (in_quotes)
        {
            if (c == '"')
            {
                if (i + 1 < line.size() && line[i + 1] == '"')
                {
                    field.push_back('"');
                    ++i;
                }
                else
                {
                    in_quotes = false;
                }
            }
            else
                field.push_back(c);
        }
        else
        {
            if (c == '"')
                in_quotes = true;
            else if (c == ',')
            {
                out.push_back(field);
                field.clear();
            }
            else
                field.push_back(c);
        }
    }
    out.push_back(field);
    return out;
}

std::fstream &GotoLine(std::fstream &file, unsigned int num)
{
    file.seekg(std::ios::beg);
    for (uint i = 0; i < num - 1; ++i)
    {
        file.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    return file;
}

/*=============== Actual Emulator Functions ===============*/

int Emulator::setFlag(int vcpu, vcpu_operation_t cmd) {
    // Set the flag to be the cmd
    flags[vcpu].store(flags[vcpu].load(std::memory_order_relaxed) | cmd, std::memory_order_relaxed); 

    // Get how many shifts the flag was at ( 0b01000 would = 3 )
    uint64_t flagIndex = std::countr_zero(static_cast<uint64_t>(cmd));

    return 0;
}


int Emulator::removeFlag(int vcpu, vcpu_operation_t cmd) {
    // FLAGS AND (FLAGS AND NOT CMD) = turning off only the inputted flag
    flags[vcpu].store(flags[vcpu].load(std::memory_order_relaxed) & (~cmd), std::memory_order_relaxed);
    return 0;
}

bool Emulator::getIsFlagQueued(int vcpu, vcpu_operation_t cmd) {
    return (flags[vcpu].load(std::memory_order_relaxed) & cmd) == cmd;
}

int Emulator::startEmulation(const std::string &executablePathArg)
{
    // ---- hardcoded paths (match your shell snippet) ----

    // Find the QEMU directory
    std::string qemuPath = ::getenv("SCALLOP_QEMU_BUILD") ? ::getenv("SCALLOP_QEMU_BUILD") : "";
    qemuPath += "/qemu-";
    qemuPath += ::getenv("SYSTEM") ? "system-" : "";
    qemuPath += ::getenv("ARCH") ? ::getenv("ARCH") : "x86_64";

    // Outputs for QEMU
    std::string currentWorkingDir = ::getenv("PWD") ? ::getenv("PWD") : "";
    std::string qemuTraceLog = currentWorkingDir;
    std::string pluginPath = ::getenv("SCALLOP_QEMU_PLUGIN") ? ::getenv("SCALLOP_QEMU_PLUGIN") : currentWorkingDir + "/qemu-plugins/";
    std::string csvPath = "/tmp";
    qemuTraceLog += "/qemu.log";
    std::cout << pluginPath << std::endl;
    pluginPath += "/scallop_plugin.so";
    std::cout << pluginPath << std::endl;
    csvPath += "/branchPPPPlog.csv";

    /*
    OUT_TO_FILE(::getenv("ARCH") ? ::getenv("ARCH") : "<null>");
    OUT_TO_FILE(" ");
    OUT_TO_FILE(::getenv("SCALLOP_QEMU_BUILD") ? ::getenv("SCALLOP_QEMU_BUILD") : "<null>");
    OUT_TO_FILE(" ");
    OUT_TO_FILE(::getenv("SCALLOP_QEMU_PLUGIN") ? ::getenv("SCALLOP_QEMU_PLUGIN") : "<null>");

    OUT_TO_FILE("\n\n");*/

    // Path to the executable being debugged
    static std::string executablePath = executablePathArg;

    // If there's a child process of QEMU, nuke it
    if (child_pid_ != -1)
        kill(child_pid_, SIGKILL); // Kill the child process

    // Clean up previous CSV; we can’t glob /tmp/branchlog.*.sock here, but that’s fine.
    //::unlink(csvPath.c_str());

    // ---- build argv: qemu -d plugin -D <log> -plugin <.so> -- <target> ----
    std::vector<std::string> args_str = {
        qemuPath,
        "-d", "plugin",
        "-D", qemuTraceLog,
        "-plugin", pluginPath,
        "--",
        executablePath};

    // If there's a new binary then replace the executable path
    if (executablePathArg != "")
    {
        executablePath = executablePathArg;
    }

    // Put everything in argv to prepare it for qemu
    std::vector<char *> argv;
    argv.reserve(args_str.size() + 1);
    for (auto &s : args_str)
    {
        argv.push_back(const_cast<char *>(s.c_str()));
        OUT_TO_FILE(s + " ");
    }
    argv.push_back(nullptr);

    // ---- set up a pipe to capture child's stdout+stderr ----
    int pipefd[2];
    if (::pipe(pipefd) != 0)
    {
        perror("pipe");
        return -1;
    }

    // ---- fork/exec QEMU ----
    pid_t pid = ::fork();

    if (pid < 0)
    {
        perror("fork");
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return -1;
    }
    if (pid == 0)
    {

        // redirect stdout/stderr to pipe write end
        //::dup2(pipefd[1], STDOUT_FILENO);
        //::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        ::execv(argv[0], argv.data());
        perror("done with QEMU");
        _exit(127);
    }

    child_pid_ = pid;

    // If socket fails to initialize
    if (socket.initialize() != 0)
    {
        perror("socket failed to initialize!");
    }

    // parent
    child_pid_ = pid;
    ::close(pipefd[1]); // parent reads from pipefd[0]

    return child_pid_;
}

int Emulator::addBreakpoint(uint64_t address, std::string &comment)
{
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "break 0x%llx\n", address);
    fprintf(stderr, "%s", cmd);
    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    return 0;
}

int Emulator::modifyMemory(uint64_t address, std::vector<uint8_t>* data, int n) {
   
    if (getIsFlagQueued(0, VCPU_OP_SET_MEM) == false) 
        return 1;
    
    if (data == nullptr) {
        return 1;
    }

    // If data is empty OR bytes is <= 0 then ret
    if (data->empty() || n <= 0)
        return 1;

    const int copy_len = std::min(n, static_cast<int>(data->size()));
    std::string ret;
    std::string memoryDumpWrite; // String to save to file
    memoryDumpWrite.reserve(static_cast<size_t>(copy_len) * 3);

    // For each byte
    for (int i = 0; i < copy_len; ++i)
    {
        // Add to the memdump file
        memoryDumpWrite += hex1ByteStr(data->at(i));

        // If it's the 8th byte, newline
        if (((i + 1) % 8) == 0)
            memoryDumpWrite.push_back('\n');
        else
            memoryDumpWrite.push_back(' ');
    }

    // If it runs out early, add a newline at the end
    if (!memoryDumpWrite.empty() && memoryDumpWrite.back() != '\n')
        memoryDumpWrite.back() = '\n';

    // If writing the whole file works
    if (!writeWholeFile(kMemDump, memoryDumpWrite))
        return 1;

    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx %d\n",
                  (unsigned long long)address, copy_len);
    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return 1;

    
    removeFlag(0, VCPU_OP_SET_MEM);
    return 0;

}

int Emulator::modifyMemory(uint64_t address, uint8_t *data, int n)
{
    return 0;
    /*
    if (getIsFlagQueued(0, VCPU_OP_SET_MEM) == false) 
        return 0;
    
    // If data = nullptr OR bytes is <= 0 then ret
    if (!data || n <= 0)
        return 0;
    
    std::string ret;
    std::string memoryDumpWrite; // String to save to file
    memoryDumpWrite.reserve(static_cast<size_t>(n) * 3);

    // For each byte
    for (int i = 0; i < n; ++i)
    {
        // Add to the memdump file
        memoryDumpWrite += hex1ByteStr(data[i]);

        // If it's the 8th byte, newline
        if (((i + 1) % 8) == 0)
            memoryDumpWrite.push_back('\n');
        else
            memoryDumpWrite.push_back(' ');
    }

    // If it runs out early, add a newline at the end
    if (!memoryDumpWrite.empty() && memoryDumpWrite.back() != '\n')
        memoryDumpWrite.back() = '\n';

    // If writing the whole file works
    if (!writeWholeFile(kMemDump, memoryDumpWrite))
        return 0;

    uint64_t span = static_cast<uint64_t>(n - 1);
    uint64_t hi = address;
    if (span > std::numeric_limits<uint64_t>::max() - address)
        hi = std::numeric_limits<uint64_t>::max();
    else
        hi = address + span;

    // Send the command
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx;0x%llx\n",
                  (unsigned long long)address, (unsigned long long)hi);
    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
        return false;

    return ret.rfind("ok", 0) == 0; */
}

void Emulator::stageMemoryWrite(uint64_t address, const std::vector<uint8_t>& data, int n)
{
    if (n <= 0 || data.empty())
    {
        return;
    }
    PendingSetMem staged;
    staged.address = address;
    staged.size = std::min(n, static_cast<int>(data.size()));
    staged.data.assign(data.begin(), data.begin() + staged.size);

    std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
    g_pending_setmem = std::move(staged);
}

bool Emulator::hasStagedMemoryWrite()
{
    std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
    return g_pending_setmem.has_value();
}

int Emulator::flushStagedMemoryWrite()
{
    PendingSetMem staged;
    {
        std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
        if (!g_pending_setmem)
        {
            return 0;
        }
        staged = *g_pending_setmem;
        g_pending_setmem.reset();
    }

    int rc = modifyMemory(staged.address, &staged.data, staged.size);
    if (rc != 0)
    {
        std::lock_guard<std::mutex> lock(g_pending_setmem_mu);
        g_pending_setmem = std::move(staged);
    }
    return rc;
}

int Emulator::focusMemory(uint64_t lowAddress, uint64_t highAddress)
{
    std::string ret;
    std::string exit = socket.sendCommand(std::to_string(lowAddress) + ';' + std::to_string(highAddress) + '\n');
    return 0;
}

namespace
{
    struct MemoryCache
    {
        bool tryUpdateAgain = false;
        int modificationsMade = 0;
        int targetModifications = 0;
        uint64_t address = std::numeric_limits<uint64_t>::max();
        int span = -1;
        std::vector<uint8_t> data;
    };

    static std::unordered_map<std::string, MemoryCache> &memoryCaches()
    {
        static std::unordered_map<std::string, MemoryCache> caches;
        return caches;
    }
} // namespace

std::vector<uint8_t>* Emulator::getMemory(uint64_t address, int n,
                                          int targetMods, const std::string &cacheKey)
{
    auto &cache = memoryCaches()[cacheKey];
    const uint64_t kNoAddress = std::numeric_limits<uint64_t>::max();

    // If addr = -1 was passed in, save it to the cache
    if (address != kNoAddress)
        cache.address = address;

    // If size changed, store it in cache.span
    if (n != -1)
        cache.span = n;

    // If the cache address = -1 or the size is less than 1
    if (cache.address == kNoAddress || cache.span <= 0)
    {
        return &cache.data; // Ret the data (probably nullptr)
    }
    
    const bool update_requested = getIsFlagQueued(0, VCPU_OP_DUMP_MEM);
    // If the flag isn't here and it isn't supposed to update again:
    if (!update_requested && !cache.tryUpdateAgain)
    {
        return &cache.data; // Return the old data
    }

    // Return how many times getMemory has to change 
    if (targetMods != -1)
    {
        cache.targetModifications = targetMods;
    }

    if (!update_requested)
    {
        return &cache.data;
    }

    fprintf(stderr, "flag is queued, ready to get memory\n");

    // Decremement span because it's going to do another modification
    uint64_t span = static_cast<uint64_t>(cache.span - 1);
    uint64_t hi = cache.address;

    if (span > std::numeric_limits<uint64_t>::max() - cache.address)
        hi = std::numeric_limits<uint64_t>::max();
    else
        hi = cache.address + span;

    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "get memory 0x%llx %d\n",
                  (unsigned long long)cache.address, n);

    fprintf(stderr, "%s\n", cmd);

    if (socket.sendCommand(cmd).compare(0, 2, "ok") != 0)
    {
        cache.tryUpdateAgain = true;
        fprintf(stderr, "     trying again, didnt send ok back\n");
        return &cache.data;
    }

    fprintf(stderr, "sent command\n");

    std::ifstream memoryFile(kMemDump, std::ios::in);
    if (!memoryFile.is_open())
    {

        fprintf(stderr, "memory file is not open\n");

        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    std::vector<std::string> bytes;
    std::string memoryDumpLine;
    while (std::getline(memoryFile, memoryDumpLine))
    {
        std::stringstream check1(memoryDumpLine);
        std::string intermediate;
        while (std::getline(check1, intermediate, ' '))
        {
            if (!intermediate.empty())
                bytes.push_back(intermediate);
        }
    }

    if (bytes.empty())
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    cache.data.clear();
    cache.data.reserve(bytes.size());
    for (const auto &byte : bytes)
    {
        uint8_t byteInt = 0;
        if (sscanf(byte.c_str(), "%hhx", &byteInt) == 1)
            cache.data.emplace_back(byteInt);
    }

    if (cache.data.empty())
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }

    if (cache.data.size() > static_cast<size_t>(cache.span))
        cache.data.resize(static_cast<size_t>(cache.span));

    const bool should_clear_flag = update_requested;
    if (cache.targetModifications > 0)
    {
        cache.modificationsMade++;
        if (cache.modificationsMade >= cache.targetModifications)
        {
            cache.targetModifications = 0;
            cache.modificationsMade = 0;
            cache.tryUpdateAgain = false;
            if (should_clear_flag)
            {
                removeFlag(0, VCPU_OP_DUMP_MEM);
            }
        }
        else
        {
            cache.tryUpdateAgain = true;
        }
    }
    else
    {
        cache.modificationsMade = 0;
        cache.tryUpdateAgain = false;
        if (should_clear_flag)
        {
            removeFlag(0, VCPU_OP_DUMP_MEM);
        }
    }

    return &cache.data;
}

std::vector<std::string> *Emulator::getRegisters()
{
    static bool tryagain = true;
    static std::vector<std::string> registers;

    const bool update_requested = getIsFlagQueued(0, VCPU_OP_DUMP_REGS);
    if (!update_requested && !tryagain)
    {
        return &registers;
    }

    // Request registers (either because a refresh was requested or we're still waiting on a retry)
    if (socket.sendCommand("get registers\n").compare(0, 2, "ok") != 0)
    {
        OUT_TO_FILE("got ok\n");
        tryagain = true;
        return &registers;
    }
    else
    {
        OUT_TO_FILE("still sent the command but no ok\n");
    }

    // Open regdump
    std::ifstream regDump(kRegDump, std::ios::in);
    if (!regDump.is_open())
    {
        tryagain = true;
        return &registers;
    }

    std::vector<std::string> registersTemp;
    std::string line;
    while (std::getline(regDump, line))
    {
        if (!line.empty())
        {
            registersTemp.emplace_back(line);
        }
    }
    regDump.close();

    if (!registersTemp.empty())
    {
        registers = std::move(registersTemp);
        tryagain = false;
        if (update_requested)
        {
            removeFlag(0, VCPU_OP_DUMP_REGS);
        }
    }

    return &registers;
}

int Emulator::setRegister(std::string reg_name, uint64_t value)
{
    (void)reg_name;
    (void)value;
    return 0;
}

std::shared_ptr<std::pair<uint64_t, uint64_t>>
Emulator::getInstructionJumpPaths(uint64_t address)
{
    (void)address;
    return nullptr;
}

int Emulator::step(int steps)
{
    if (hasStagedMemoryWrite())
    {
        setFlag(0, VCPU_OP_SET_MEM);
        if (flushStagedMemoryWrite() != 0)
        {
            fprintf(stderr, "[scallop] failed to stage memory write\n");
            removeFlag(0, VCPU_OP_SET_MEM);
        }
    }

    std::string ret;
    bool exitCode = socket.sendCommand(std::string("step ") + std::to_string(steps)).compare(0, 2, "ok") != 0;
    setFlag(0, VCPU_OP_DUMP_MEM);
    setFlag(0, VCPU_OP_DUMP_REGS);
    setFlag(0, VCPU_OP_SET_REGS);
    getRegisters();
    return exitCode;
}

int Emulator::continueExec()
{
    if (hasStagedMemoryWrite())
    {
        setFlag(0, VCPU_OP_SET_MEM);
        if (flushStagedMemoryWrite() != 0)
        {
            fprintf(stderr, "[scallop] failed to stage memory write\n");
            removeFlag(0, VCPU_OP_SET_MEM);
        }
    }

    std::string ret;
    bool exitCode = socket.sendCommand("resume").compare(0, 2, "ok") != 0;
    setFlag(0, VCPU_OP_DUMP_MEM);
    setFlag(0, VCPU_OP_DUMP_REGS);
    setFlag(0, VCPU_OP_SET_REGS);
    return exitCode;
}

std::string Emulator::disassembleInstruction(uint64_t address,
                                             std::shared_ptr<uint8_t> data, int n)
{
    (void)address;
    (void)data;
    (void)n;
    return {};
}

bool Emulator::getIsEmulating()
{
    return isEmulating;
}

std::vector<InstructionInfo>* Emulator::getRunInstructions(
    int start_line,
    int n,
    bool* updated,
    int* total_lines_out
) {
    static const char* kCsvPath = "/tmp/branchlog.csv";

    static int cached_start = -1, cached_n = -1;
    static uintmax_t cached_size = 0;
    static std::time_t cached_mtime = 0;
    static int cached_total_lines = 0;

    // ---------- file state ----------
    std::error_code ec;
    auto sz = std::filesystem::file_size(kCsvPath, ec);
    std::time_t mt = 0;

    if (!ec) { 
        auto ft = std::filesystem::last_write_time(kCsvPath, ec);
        if (!ec) {
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ft - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
            mt = std::chrono::system_clock::to_time_t(sctp);
        }
    }

    const bool file_unchanged =
        (cached_start == start_line && cached_n == n && sz == cached_size && mt == cached_mtime);

    if (file_unchanged) {
        if (updated) *updated = false;
        if (total_lines_out) *total_lines_out = cached_total_lines;
        return &instructionInfo;
    }

    // file changed or request changed
    if (updated) *updated = true;

    instructionInfo.clear();

    std::ifstream f(kCsvPath, std::ios::in | std::ios::binary);
    if (!f) {
        cached_start = start_line;
        cached_n = n;
        cached_size = sz;
        cached_mtime = mt;
        cached_total_lines = 0;
        if (total_lines_out) *total_lines_out = 0;
        return &instructionInfo;
    }

    // ---------- header handling ----------
    std::string line;

    bool first_line_is_data = false;
    std::streampos after_first = 0;

    if (std::getline(f, line)) {
        std::string t = trim(line);
        first_line_is_data = (t.size() >= 3 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'));
        after_first = f.tellg();
    }

    // If first line was header: keep stream after it.
    // If first line was data: rewind so we include it in counting and paging.
    if (first_line_is_data) {
        f.clear();
        f.seekg(0, std::ios::beg);
    } else {
        // already consumed header; keep going
        // (we are currently positioned after first line)
    }

    // ---------- count + page in one pass ----------
    int data_index = 0;       // counts ONLY valid data rows
    int returned = 0;
    int total_data_rows = 0;

    while (std::getline(f, line)) {
        std::string s = trim(line);
        if (s.empty()) continue;

        auto cols = parse_csv(s);
        if (cols.size() < 6) continue; // minimum columns when symbol is present

        const std::string& c0 = cols[0];
        if (c0.size() < 3 || !(c0[0] == '0' && (c0[1] == 'x' || c0[1] == 'X')))
            continue; // not a data row

        // This is a data row
        total_data_rows++;

        // If it's inside the requested window, parse & store it
        if (data_index >= start_line && (n <= 0 || returned < n)) {
            uint64_t pc = parse_hex(cols[0]);
            std::string disType = trim(cols[1]);
            uint64_t bt = parse_hex(cols[2]);
            uint64_t ft = parse_hex(cols[3]);

            // CSV layout (when disassembly is enabled):
            // pc,kind,branch_target,fallthrough,tb_vaddr,disas,symbol
            // Disassembly column is optional, but symbol is always the last field.
            std::string dis;
            std::string symbol;
            if (cols.size() >= 7) {
                dis = trim(cols[5]);
                symbol = trim(cols[6]);
            } else {
                dis.clear();
                symbol = trim(cols.back());
            }

            if (disType.empty()) {
                // your fallback classify logic (unchanged)
                size_t i = 0;
                while (i < dis.size() && std::isspace((unsigned char)dis[i])) ++i;
                size_t j = i;
                while (j < dis.size() && !std::isspace((unsigned char)dis[j])) ++j;
                std::string m = dis.substr(i, j - i);
                for (char &c : m) c = (char)std::tolower((unsigned char)c);

                if (m == "ret" || m == "retq" || m == "retn" || m == "iret") disType = "ret";
                else if (m == "jmp" || m == "ljmp") disType = "jmp";
                else if (m == "call" || m == "callq" || m == "lcall") disType = "call";
                else if (!m.empty() && m[0] == 'j' && m != "jmp") disType = "cond";
                else disType = "other";
            }

            instructionInfo.emplace_back(std::move(dis), std::move(disType), std::move(symbol), pc, bt, ft, bt ? 1u : 0u);
            ++returned;
        }

        data_index++;

        // If we've already returned n lines AND we only care about total_lines for PageDown,
        // we still need to keep counting to end-of-file. So do NOT break.
    }

    // cache bookkeeping
    cached_start = start_line;
    cached_n = n;
    cached_size = sz;
    cached_mtime = mt;
    cached_total_lines = total_data_rows;

    if (total_lines_out) *total_lines_out = total_data_rows;
    return &instructionInfo;
}
