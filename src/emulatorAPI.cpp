#include "emulatorAPI.hpp"
#include "guihelpers.hpp"
#include "debug.hpp"

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

int child_pid_ = -1;
int sock_fd_   = -1;

static constexpr const char* kSockPath   = "/tmp/scallopshell.sock";
static constexpr const char* kMemDump    = "/tmp/memdump.txt";
static constexpr const char* kRegDump    = "/tmp/regdump.txt";


bool Emulator::isEmulating = false;
static std::vector<InstructionInfo> instructionInfo;
    
int socket_fd() { return sock_fd_; }
int pid() { return child_pid_; }


uint64_t Emulator::getRegisterValue(std::string registerArg) {
    std::vector<std::string>* regs = Emulator::getRegisters(false, -1);
    if (!regs) return 0;

    for (const std::string& line : *regs) {
        if (line.rfind(registerArg + "=", 0) == 0) { // starts with "rip="
            const char* valStr = line.c_str() + 4; // skip "rip="
            uint64_t val = strtoull(valStr, NULL, 16);
            return val;
        }
    }

    return 0; // not found
}


static int connectWithRetryUnix(const std::string& path,
                                std::chrono::milliseconds total_timeout =
                                    std::chrono::seconds(5),
                                std::chrono::milliseconds backoff =
                                    std::chrono::milliseconds(100)) {
    auto start = std::chrono::steady_clock::now();
    while (true) {
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        if (path.size() >= sizeof(addr.sun_path)) {
            ::close(fd);
            errno = ENAMETOOLONG;
            return -1;
        }
        ::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
            return fd;

        int e = errno;
        ::close(fd);
        if (std::chrono::steady_clock::now() - start >= total_timeout) {
            errno = e;
            return -1;
        }
        std::this_thread::sleep_for(backoff);
    }
}

static bool connectUnixOnce(const std::string& path, int& out_fd) {
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return false;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        errno = ENAMETOOLONG;
        return false;
    }
    ::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }
    out_fd = fd;
    return true;
}

static bool readAllFromFd(int fd, std::string& out) {
    out.clear();
    char buf[4096];
    while (true) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            out.append(buf, buf + n);
        } else if (n == 0) {
            return true; // peer closed; done
        } else {
            if (errno == EINTR) continue;
            return false;
        }
    }
}

bool sendCommandOnce(const std::string& cmd, std::string* reply) {
    int fd;
    if (!connectUnixOnce(kSockPath, fd)) {
        return false;
    }

    // Ensure trailing newline (your socat examples send a single line)
    std::string line = cmd;
    if (line.empty() || line.back() != '\n') line.push_back('\n');

    ssize_t off = 0;
    while (off < (ssize_t)line.size()) {
        ssize_t n = ::send(fd, line.data() + off, line.size() - off, 0);
        if (n > 0) off += n;
        else if (n < 0 && errno == EINTR) continue;
        else { ::close(fd); return false; }
    }

    bool ok = true;
    if (reply) {
        ok = readAllFromFd(fd, *reply);
    }
    ::shutdown(fd, SHUT_RDWR);
    ::close(fd);
    return ok;
}

bool readWholeFile(const std::string& path, std::string& out) {
    std::ifstream ifs(path, std::ios::in | std::ios::binary);
    if (!ifs) return false;
    out.assign(std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>());
    return true;
}

bool writeWholeFile(const std::string& path, const std::string& contents) {
    std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs) return false;
    ofs.write(contents.data(), (std::streamsize)contents.size());
    return ofs.good();
}

bool writeWholeFile(const std::string& path, const uint8_t* data, int n) {
    if (!data || n <= 0)
        return false;

    std::ofstream ofs(path, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!ofs)
        return false;

    ofs.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(n));
    return ofs.good();
}

static std::string trim(std::string s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string{};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static uint64_t parse_hex(const std::string& s) {
    std::string t = trim(s);
    if (t.empty() || t == "0" || t == "0x0") return 0ULL;
    const char* p = t.c_str();
    if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) p += 2;
    char* end = nullptr;
    unsigned long long v = std::strtoull(p, &end, 16);
    return static_cast<uint64_t>(v);
}

static std::vector<std::string> parse_csv(const std::string& line) {
    std::vector<std::string> out;
    std::string field;
    bool in_quotes = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (in_quotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') { field.push_back('"'); ++i; }
                else { in_quotes = false; }
            } else field.push_back(c);
        } else {
            if (c == '"') in_quotes = true;
            else if (c == ',') { out.push_back(field); field.clear(); }
            else field.push_back(c);
        }
    }
    out.push_back(field);
    return out;
}

std::fstream& GotoLine(std::fstream& file, unsigned int num){
    file.seekg(std::ios::beg);
    for(uint i=0; i < num - 1; ++i){
        file.ignore(std::numeric_limits<std::streamsize>::max(),'\n');
    }
    return file;
}

// emulatorAPI.cpp
static bool sendCommandNoReply(const std::string& cmd) {
    int fd;
    if (!connectUnixOnce(kSockPath, fd)) return false;
    std::string line = cmd;
    if (line.empty() || line.back() != '\n') line.push_back('\n');
    ssize_t off = 0;
    while (off < (ssize_t)line.size()) {
        ssize_t n = ::send(fd, line.data() + off, line.size() - off, 0);
        if (n > 0) off += n;
        else if (n < 0 && errno == EINTR) continue;
        else { ::close(fd); return false; }
    }
    ::shutdown(fd, SHUT_WR);   // we’re done sending
    ::close(fd);               // don’t wait for plugin
    return true;
}

/*=============== Actual Emulator Functions ===============*/

int Emulator::startEmulation(const std::string& executablePathArg) {
    // ---- hardcoded paths (match your shell snippet) ----
    const std::string qemuSocket = "/tmp/scallopshell.sock";
    const std::string qemuPath = ( ::getenv("QEMU_BUILD")
        ? std::string(::getenv("QEMU_BUILD")) + "/qemu-x86_64"
        : std::string("/home/bradley/Downloads/qemu/build/qemu-x86_64") );

    const std::string qemuTraceLog = "/home/bradley/SoftDev/ScallopShell/qemu.log";
    const std::string pluginPath   = "/home/bradley/Downloads/qemu/plugins/branchlog.so";
    const std::string csvPath      = "/home/bradley/SoftDev/ScallopShell/branchlog.csv";

    static std::string executablePath = executablePathArg;

    std::ofstream ofs(csvPath,
                  std::ios::out | std::ios::trunc);
    ofs.close();

    if (child_pid_ != -1) kill(child_pid_, SIGKILL); // Kill the child process

    // Clean up previous CSV; we can’t glob /tmp/branchlog.*.sock here, but that’s fine.
    ::unlink(csvPath.c_str());



    // ---- build argv: qemu -d plugin -D <log> -plugin <.so> -- <target> ----
    std::vector<std::string> args_str;
    

    if (executablePathArg == "") {
        args_str = {
        qemuPath,
        "-d", "plugin",
        "-D", qemuTraceLog,
        "-plugin", pluginPath,
        "--",
        executablePath };
    }
    else {
        args_str = {
        qemuPath,
        "-d", "plugin",
        "-D", qemuTraceLog,
        "-plugin", pluginPath,
        "--",
        executablePath };

        executablePath = executablePathArg;
    }

    std::vector<char*> argv; argv.reserve(args_str.size()+1);
    for (auto& s : args_str) argv.push_back(const_cast<char*>(s.c_str()));
    argv.push_back(nullptr);

    // ---- set up a pipe to capture child's stdout+stderr ----
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }

    // ---- fork/exec QEMU ----
    pid_t pid = ::fork();

    
    if (pid < 0) {
        perror("fork");
        ::close(pipefd[0]); ::close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        // child
        //::setsid();
        // redirect stdout/stderr to pipe write end
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        ::execv(argv[0], argv.data());
        perror("execv qemu-x86_64");
        _exit(127);
    }

    child_pid_ = pid;


    // wait up to 10 seconds for /tmp/scallopshell.sock to appear
    const char* sockPath = "/tmp/scallopshell.sock";
    for (int i = 0; i < 100; i++) {
        struct stat st;
        if (stat(sockPath, &st) == 0 && S_ISSOCK(st.st_mode))
            break; // socket ready
        usleep(100000); // 100ms
    }


    // parent
    child_pid_ = pid;
    ::close(pipefd[1]); // parent reads from pipefd[0]

    // open CSV for writing (truncate)
    int csv_fd = ::open(csvPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (csv_fd < 0) {
        perror("open csv");
        // we’ll still run, just won’t save CSV
    }

    // Reader thread: pump child output, capture control-socket line, write CSV otherwise
    int rfd = pipefd[0];
    std::string captured_sock_path;  // filled when we see the control line

    std::thread pump([rfd, csv_fd, &captured_sock_path]() {
        char buf[4096];
        std::string linebuf;
        auto write_csv_line = [&](const std::string& line) {
            if (csv_fd >= 0) {
                // write line + '\n'
                (void)::write(csv_fd, line.data(), line.size());
                (void)::write(csv_fd, "\n", 1);
            }
        };

        for (;;) {
            ssize_t n = ::read(rfd, buf, sizeof(buf));
            if (n <= 0) break;
            linebuf.append(buf, buf + n);
            // process complete lines
            size_t pos;
            while ((pos = linebuf.find('\n')) != std::string::npos) {
                std::string line = linebuf.substr(0, pos);
                // drop trailing \r if any
                if (!line.empty() && line.back() == '\r') line.pop_back();

                // Detect control-socket announcement:
                // format: "[branchlog] control socket: /tmp/branchlog.<pid>.sock"
                static const char* kPrefix = "[branchlog] control socket:";
                if (line.compare(0, strlen(kPrefix), kPrefix) == 0) {
                    // take last 'word' as path
                    size_t sp = line.find_last_of(' ');
                    if (sp != std::string::npos && sp + 1 < line.size()) {
                        captured_sock_path = line.substr(sp + 1);
                    }
                    // DO NOT write this line to CSV
                } else {
                    write_csv_line(line); // pass-through to CSV
                }
                linebuf.erase(0, pos + 1);
            }
        }

        // flush any partial last line (rare; usually CSV lines end with \n)
        if (!linebuf.empty()) {
            // don’t treat as control socket; just write it as a CSV tail line
            if (csv_fd >= 0) {
                (void)::write(csv_fd, linebuf.data(), linebuf.size());
            }
        }

        if (csv_fd >= 0) ::close(csv_fd);
        ::close(rfd);
    });

    // Wait up to ~5s for the socket path to appear, then connect.
    // (busy-wait with short sleeps to avoid pulling in <condition_variable>)
    const auto t0 = std::chrono::steady_clock::now();
    std::string sock_path_seen;
    while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(5)) {
        // copy from the thread's captured string if it has been set
        // (no mutex; benign data race on read of std::string contents after it stabilizes)
        if (!sock_path_seen.size()) sock_path_seen = captured_sock_path;
        if (!sock_path_seen.empty()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }


    if (!sock_path_seen.empty()) {
        sock_fd_ = connectWithRetryUnix(sock_path_seen,
                                        std::chrono::seconds(10),
                                        std::chrono::milliseconds(100));
        if (sock_fd_ < 0) {
            perror("connect to plugin socket");
            isEmulating = true;
            // optional: ::kill(child_pid_, SIGTERM);
        }
    } else {
        // didn’t see the control socket line in time
        // optional: perror-like notice to stderr
        ::fprintf(stderr, "startEmulation: control socket path not observed\n");
    }

    // Detach the pump thread; it keeps streaming CSV until QEMU exits.
    pump.detach();

    return child_pid_;
}

int Emulator::addBreakpoint(uint64_t address, std::string& comment) {
    (void)address; (void)comment;
    return 0;
}

int Emulator::modifyMemory(uint64_t address, uint8_t* data, int n) {
    std::string ret;

    std::string memoryDumpWrite;

    for (int i = 0; i < n/8; i++) {
        for (int j = 0; j < 8; j++) {
            memoryDumpWrite += hex1ByteStr(data[i*8 + j]) + ' ';
        }
        memoryDumpWrite += '\n';
    }

    std::ofstream memoryFile("/tmp/memdump.txt", std::ios::out | std::ios::trunc);
    memoryFile << memoryDumpWrite;


    if (!writeWholeFile(kMemDump, data, n)) return false;
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx;0x%llx\n",
                  (unsigned long long)address, (unsigned long long)address + n);
    return sendCommandOnce(cmd, &ret);
}

int Emulator::focusMemory(uint64_t lowAddress, uint64_t highAddress) {
    std::string ret;
    bool exitCode = sendCommandNoReply(std::to_string(lowAddress) + ';' + std::to_string(highAddress) + '\n');
    return exitCode;
}

std::vector<uint8_t>* Emulator::getMemory(uint64_t address, int n, bool _update, int targetMods) {
    static bool tryUpdateAgain = false;
    static int modificationsMade = 0, targetModifications = 0;
    static std::vector<uint8_t> memory;
    static constexpr int kDefaultRange = 0x100;

    static uint64_t address_ = 0;
    static int n_ = kDefaultRange;

    if (!_update && !tryUpdateAgain) return &memory;

    // Update sticky params only when caller sets them
    if (address != (uint64_t)-1) address_ = address;
    if (n >= 0) n_ = n;

    // If you really need a guard, check that address_ has been set at least once:
    // if (!address_) return &memory;

    // Issue request using the sticky state:
    sendCommandNoReply(
    "get memory " + hex8ByteStr(address_) + ";" + hex8ByteStr(address_ + (uint64_t)n_) + "\n");

    std::fstream memoryFile("/tmp/memdump.txt", std::ios::in);
    if (!memoryFile.is_open()) {
        tryUpdateAgain = true;
        return &memory;
    }

    // Throttle re-reads by the targetMods mechanism (your existing logic)
    if (targetMods != -1) targetModifications = targetMods;
    if (modificationsMade >= targetModifications) {
        tryUpdateAgain = false; modificationsMade = 0; targetModifications = 0;
    } else {
        tryUpdateAgain = true;
    }

    // Parse: skip empties and non-hex
    std::vector<std::string> tokens;
    std::string line;
    while (std::getline(memoryFile, line)) {
        std::stringstream ss(line);
        std::string tok;
        while (std::getline(ss, tok, ' ')) {
            if (tok.size() == 2 && std::isxdigit((unsigned char)tok[0]) && std::isxdigit((unsigned char)tok[1]))
                tokens.emplace_back(tok);
        }
    }

    if (tokens.empty()) return &memory;

    memory.clear();
    memory.reserve(tokens.size());
    for (const auto& t : tokens) {
        unsigned int v = 0; // use unsigned int to check conversion result cleanly
        std::sscanf(t.c_str(), "%x", &v);
        memory.emplace_back((uint8_t)v);
    }
    modificationsMade++;
    return &memory;
}

std::vector<std::string>* Emulator::getRegisters(bool _update, int targetMods) {
    
    static bool tryUpdateAgain = false;
    static int modificationsMade = 0;
    static int targetModifications = 0;
    static std::vector<std::string> registers = {};

    

    if (_update == false && tryUpdateAgain == false) return &registers;
    
    if (targetMods != -1) targetModifications = targetMods;

    std::fstream regDump("/tmp/regdump.txt");
    
    if (!regDump.is_open()) {
        tryUpdateAgain = true;
        return &registers;
    }

    if (modificationsMade >= targetModifications) {
        tryUpdateAgain = false;
        modificationsMade = 0;
        targetModifications = 0;
    }
    else {
        tryUpdateAgain = true;
    }

    // If its told by step() to update, then reparse the regdump
    std::vector<std::string> registersTemp;

    std::string temp; 
    while (std::getline(regDump, temp)) {
        registersTemp.emplace_back(temp);
    }

    if (registersTemp.empty()) tryUpdateAgain = true;
    else {
        registers.clear();
        registers = registersTemp;
        modificationsMade++;
    }


    regDump.close();

    return &registers;
}

int Emulator::setRegister(std::string reg_name, uint64_t value) {
    (void)reg_name; (void)value;
    return 0;
}

std::shared_ptr<std::pair<uint64_t, uint64_t>>
Emulator::getInstructionJumpPaths(uint64_t address) {
    (void)address;
    return nullptr;
}

int Emulator::step(int steps) {
    std::string ret;
    
    getRegisters(true, steps); // Send a signal to getRegisters() to update. This keeps it performant
    getMemory(getRegisterValue("rsp"), -1, true, steps);

    bool exitCode = sendCommandNoReply("step " + std::to_string(steps) + "\n");

    //OUT_TO_FILE(hex8ByteStr(getRegisterValue("rip")));
    return exitCode;
}

int Emulator::continueExec() {
    std::string ret;
    return sendCommandOnce("resume\n", &ret);

}

std::string Emulator::disassembleInstruction(uint64_t address,
                                             std::shared_ptr<uint8_t> data, int n) {
    (void)address; (void)data; (void)n;
    return {};
}

bool Emulator::getIsEmulating() {
    return isEmulating;
}

std::vector<InstructionInfo>* Emulator::getRunInstructions(int start_line, int n, int* updated) {
    static const char* kCsvPath = "/home/bradley/SoftDev/ScallopShell/branchlog.csv";

    // simple cache of the last request & file state
    static int cached_start = -1, cached_n = -1;
    static uintmax_t cached_size = 0;
    static std::time_t cached_mtime = 0;

    // check file state
    std::error_code ec;
    auto sz = std::filesystem::file_size(kCsvPath, ec);
    std::time_t mt = 0;
    if (ec) {
        std::filesystem::file_time_type ft = std::filesystem::last_write_time(kCsvPath, ec);
        if (!ec) {
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ft - std::filesystem::file_time_type::clock::now()
                + std::chrono::system_clock::now());
            mt = std::chrono::system_clock::to_time_t(sctp);
        }
    }

    // serve from cache if request & file are unchanged
    if (cached_start == start_line && cached_n == n && sz == cached_size && mt == cached_mtime) {
        *updated = 0;
        return &instructionInfo;
    }

    instructionInfo.clear();

    // open fresh each call (cheap, robust)
    std::ifstream f(kCsvPath, std::ios::in | std::ios::binary);
    if (!f) {
        // file not there yet; keep buffer empty and update cache keys
        cached_start = start_line; cached_n = n; cached_size = sz; cached_mtime = mt;
        return &instructionInfo;
    }

    // Alert the caller that there's new instructions
    if (updated != nullptr) *updated = true;

    // read first line (header) and discard it if it isn't a PC like 0x...
    std::string line;
    if (std::getline(f, line)) {
        std::string t = trim(line);
        bool looks_pc = t.size() >= 3 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X');
        if (looks_pc) {
            // header missing; that was actually data → process below by treating it as row 0
            // Rewind to beginning of file and skip zero lines logic will re-read it.
            f.clear();
            f.seekg(0, std::ios::beg);
        }
    }
    // now skip the header line (we already consumed it if it was a true header)
    // and fast-skip start_line rows
    int to_skip = start_line;
    while (to_skip-- > 0 && std::getline(f, line)) {
        // discard
    }

    // read up to n data lines
    int added = 0;
    while ((n <= 0 || added < n) && std::getline(f, line)) {
        std::string s = trim(line);
        if (s.empty()) continue;

        // must be a data row: first column starts with 0x
        auto cols = parse_csv(s);
        if (cols.size() < 6) continue;
        const std::string& c0 = cols[0];
        if (c0.size() < 3 || !(c0[0] == '0' && (c0[1] == 'x' || c0[1] == 'X'))) continue;

        uint64_t pc  = parse_hex(cols[0]);
        std::string disType = trim(cols[1]);
        uint64_t bt  = parse_hex(cols[2]);
        uint64_t ft  = parse_hex(cols[3]);
        std::string dis = trim(cols[5]);

        // fallback classify if kind ever blank
        if (disType.empty()) {
            size_t i=0; while (i<dis.size() && std::isspace((unsigned char)dis[i])) ++i;
            size_t j=i; while (j<dis.size() && !std::isspace((unsigned char)dis[j])) ++j;
            std::string m = dis.substr(i, j-i);
            for (char& c: m) c = (char)std::tolower((unsigned char)c);
            if (m == "ret" || m == "retq" || m == "retn" || m == "iret") disType = "ret";
            else if (m == "jmp" || m == "ljmp") disType = "jmp";
            else if (m == "call" || m == "callq" || m == "lcall") disType = "call";
            else if (!m.empty() && m[0]=='j' && m!="jmp") disType = "cond";
            else disType = "other";
        }

        instructionInfo.emplace_back(std::move(dis), std::move(disType), pc, bt, ft, bt ? 1u : 0u);
        ++added;
    }

    *updated = added;
    // update cache keys
    cached_start = start_line; cached_n = n; cached_size = sz; cached_mtime = mt;
    return &instructionInfo;
}
