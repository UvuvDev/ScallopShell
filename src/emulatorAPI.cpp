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

int child_pid_ = -1;
int sock_fd_ = -1;

static constexpr const char *kMemDump = "/tmp/memdump.txt";
static constexpr const char *kRegDump = "/tmp/regdump.txt";

bool Emulator::isEmulating = false;
static std::vector<InstructionInfo> instructionInfo;

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
    std::string pluginPath = ::getenv("SCALLOP_QEMU_PLUGIN") ? ::getenv("SCALLOP_QEMU_PLUGIN") : currentWorkingDir + "/qemu-plugins/" ;
    std::string csvPath = "/tmp";
    qemuTraceLog += "/qemu.log";
    std::cout << pluginPath <<std::endl;
    pluginPath += "/scallop_plugin.so";
    std::cout << pluginPath <<std::endl;
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
    if (executablePathArg != "") {        
        executablePath = executablePathArg;
    }

    // Put everything in argv to prepare it for qemu
    std::vector<char *> argv;
    argv.reserve(args_str.size() + 1);
    for (auto &s : args_str) {
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
    if (socket.initialize() == 0)
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
    (void)address;
    (void)comment;
    return 0;
}

int Emulator::modifyMemory(uint64_t address, uint8_t *data, int n)
{
    if (!data || n <= 0)
        return false;

    std::string ret;
    std::string memoryDumpWrite;
    memoryDumpWrite.reserve(static_cast<size_t>(n) * 3);

    for (int i = 0; i < n; ++i)
    {
        memoryDumpWrite += hex1ByteStr(data[i]);
        if (((i + 1) % 8) == 0)
            memoryDumpWrite.push_back('\n');
        else
            memoryDumpWrite.push_back(' ');
    }
    if (!memoryDumpWrite.empty() && memoryDumpWrite.back() != '\n')
        memoryDumpWrite.back() = '\n';

    if (!writeWholeFile(kMemDump, memoryDumpWrite))
        return false;

    uint64_t span = static_cast<uint64_t>(n - 1);
    uint64_t hi = address;
    if (span > std::numeric_limits<uint64_t>::max() - address)
        hi = std::numeric_limits<uint64_t>::max();
    else
        hi = address + span;

    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx;0x%llx\n",
                  (unsigned long long)address, (unsigned long long)hi);
    if (socket.sendCommand(cmd).compare(0, 2, "ok"))
        return false;
    return ret.rfind("ok", 0) == 0;
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

std::vector<uint8_t> *Emulator::getMemory(uint64_t address, int n, bool _update,
                                          int targetMods, const std::string &cacheKey)
{
    auto &cache = memoryCaches()[cacheKey];
    const uint64_t kNoAddress = std::numeric_limits<uint64_t>::max();

    

    if (address != kNoAddress)
        cache.address = address;
    if (n != -1)
        cache.span = n;

    if (cache.address == kNoAddress || cache.span <= 0) {
        OUT_TO_FILE("A\n");
        return &cache.data;
    }
    if (!_update && !cache.tryUpdateAgain) {
        OUT_TO_FILE("B\n");
        return &cache.data;
    }

    if (targetMods != -1) {
        OUT_TO_FILE("C\n");
        cache.targetModifications = targetMods;
    }

    if (!_update) {
        OUT_TO_FILE("D\n");
        return &cache.data;
    }

    uint64_t span = static_cast<uint64_t>(cache.span - 1);
    uint64_t hi = cache.address;
    if (span > std::numeric_limits<uint64_t>::max() - cache.address)
        hi = std::numeric_limits<uint64_t>::max();
    else
        hi = cache.address + span;

    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "get memory 0x%llx %d\n",
                  (unsigned long long)cache.address, n);

    OUT_TO_FILE(cmd);

    if (socket.sendCommand(cmd).compare(0, 2, "ok"))
    {
        cache.tryUpdateAgain = true;
        return &cache.data;
    }


    OUT_TO_FILE("sent command!\n");


    std::ifstream memoryFile(kMemDump, std::ios::in);
    if (!memoryFile.is_open())
    {

        OUT_TO_FILE("mem file not open\n");

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

    if (cache.targetModifications > 0)
    {
        cache.modificationsMade++;
        if (cache.modificationsMade >= cache.targetModifications)
        {
            cache.targetModifications = 0;
            cache.modificationsMade = 0;
            cache.tryUpdateAgain = false;
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
    }

    return &cache.data;
}

std::vector<std::string> *Emulator::getRegisters(bool _update)
{
    static bool tryagain = true;
    static std::vector<std::string> registers;

    if (_update)
    {
        tryagain = true;
    }

    if (!tryagain)
    {
        return &registers;
    }

    // Request registers
    if (socket.sendCommand("get registers\n").compare(0, 2, "ok"))
    {
        OUT_TO_FILE("got ok\n");
        return &registers;
    }
    else {
        OUT_TO_FILE("still sent the command but no ok\n");
    }    

    // Open regdump
    std::ifstream regDump(kRegDump, std::ios::in);
    if (!regDump.is_open())
    {
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
    std::string ret;
    bool exitCode = socket.sendCommand(std::string("step ") + std::to_string(steps)).compare(0, 2, "ok");
    getRegisters(true); // mark cached registers dirty so UI reloads from file
    return exitCode;
}

int Emulator::continueExec()
{
    std::string ret;
    return socket.sendCommand("resume").compare(0, 2, "ok");
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

std::vector<InstructionInfo> *Emulator::getRunInstructions(int start_line, int n, int *updated)
{
    static const char *kCsvPath = "/tmp/branchlog.csv";

    // simple cache of the last request & file state
    static int cached_start = -1, cached_n = -1;
    static uintmax_t cached_size = 0;
    static std::time_t cached_mtime = 0;

    
    // check file state
    std::error_code ec;
    auto sz = std::filesystem::file_size(kCsvPath, ec);
    std::time_t mt = 0;
    if (ec)
    {
        std::filesystem::file_time_type ft = std::filesystem::last_write_time(kCsvPath, ec);
        if (!ec)
        {
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ft - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
            mt = std::chrono::system_clock::to_time_t(sctp);
        }
    }

    // serve from cache if request & file are unchanged
    if (cached_start == start_line && cached_n == n && sz == cached_size && mt == cached_mtime)
    {
        *updated = 0;
        return &instructionInfo;
    }

    instructionInfo.clear();

    // open fresh each call (cheap, robust)
    std::ifstream f(kCsvPath, std::ios::in | std::ios::binary);
    if (!f)
    {
        // file not there yet; keep buffer empty and update cache keys
        cached_start = start_line;
        cached_n = n;
        cached_size = sz;
        cached_mtime = mt;
        return &instructionInfo;
    }

    // Alert the caller that there's new instructions
    if (updated != nullptr)
        *updated = true;

    // read first line (header) and discard it if it isn't a PC like 0x...
    std::string line;
    if (std::getline(f, line))
    {
        std::string t = trim(line);
        bool looks_pc = t.size() >= 3 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X');
        if (looks_pc)
        {
            // header missing; that was actually data → process below by treating it as row 0
            // Rewind to beginning of file and skip zero lines logic will re-read it.
            f.clear();
            f.seekg(0, std::ios::beg);
        }
    }
    // now skip the header line (we already consumed it if it was a true header)
    // and fast-skip start_line rows
    int to_skip = start_line;
    while (to_skip-- > 0 && std::getline(f, line))
    {
        // discard
    }

    // read up to n data lines
    int added = 0;
    while ((n <= 0 || added < n) && std::getline(f, line))
    {
        std::string s = trim(line);
        if (s.empty())
            continue;

        // must be a data row: first column starts with 0x
        auto cols = parse_csv(s);
        if (cols.size() < 5)
            continue;
        const std::string &c0 = cols[0];
        if (c0.size() < 3 || !(c0[0] == '0' && (c0[1] == 'x' || c0[1] == 'X')))
            continue;

        uint64_t pc = parse_hex(cols[0]);
        std::string disType = trim(cols[1]);
        uint64_t bt = parse_hex(cols[2]);
        uint64_t ft = parse_hex(cols[3]);
        std::string dis;
        if (cols.size() >= 6)
            dis = trim(cols[5]);
        else
            dis.clear();

        // fallback classify if kind ever blank
        if (disType.empty())
        {
            size_t i = 0;
            while (i < dis.size() && std::isspace((unsigned char)dis[i]))
                ++i;
            size_t j = i;
            while (j < dis.size() && !std::isspace((unsigned char)dis[j]))
                ++j;
            std::string m = dis.substr(i, j - i);
            for (char &c : m)
                c = (char)std::tolower((unsigned char)c);
            if (m == "ret" || m == "retq" || m == "retn" || m == "iret")
                disType = "ret";
            else if (m == "jmp" || m == "ljmp")
                disType = "jmp";
            else if (m == "call" || m == "callq" || m == "lcall")
                disType = "call";
            else if (!m.empty() && m[0] == 'j' && m != "jmp")
                disType = "cond";
            else
                disType = "other";
        }

        instructionInfo.emplace_back(std::move(dis), std::move(disType), pc, bt, ft, bt ? 1u : 0u);
        OUT_TO_FILE(dis);
        ++added;
    }

    *updated = added;
    // update cache keys
    cached_start = start_line;
    cached_n = n;
    cached_size = sz;
    cached_mtime = mt;
    return &instructionInfo;
}
