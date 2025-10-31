#include "emulatorAPI.hpp"

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

// C++
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>

int child_pid_ = -1;
int sock_fd_   = -1;

static constexpr const char* kSockPath   = "/tmp/scallopshell.sock";
static constexpr const char* kMemDump    = "/tmp/memdump.txt";
static constexpr const char* kRegDump    = "/tmp/regdump.txt";

int socket_fd() { return sock_fd_; }
int pid() { return child_pid_; }

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


/*=============== Actual Emulator Functions ===============*/

int Emulator::startEmulation(const std::string& executablePath) {
    // ---- hardcoded paths (match your shell snippet) ----
    const std::string qemuPath = ( ::getenv("QEMU_BUILD")
        ? std::string(::getenv("QEMU_BUILD")) + "/qemu-x86_64"
        : std::string("/home/bradley/Downloads/qemu/build/qemu-x86_64") );

    const std::string qemuTraceLog = "/home/bradley/SoftDev/ScallopShell/qemu.log";
    const std::string pluginPath   = "/home/bradley/Downloads/qemu/plugins/branchlog.so";
    const std::string csvPath      = "/home/bradley/SoftDev/ScallopShell/branchlog.csv";

    // Clean up previous CSV; we can’t glob /tmp/branchlog.*.sock here, but that’s fine.
    ::unlink(csvPath.c_str());

    // ---- build argv: qemu -d plugin -D <log> -plugin <.so> -- <target> ----
    std::vector<std::string> args_str = {
        qemuPath,
        "-d", "plugin",
        "-D", qemuTraceLog,
        "-plugin", pluginPath,
        "--",
        executablePath
    };
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
        ::setsid();
        // redirect stdout/stderr to pipe write end
        ::dup2(pipefd[1], STDOUT_FILENO);
        ::dup2(pipefd[1], STDERR_FILENO);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        ::execv(argv[0], argv.data());
        perror("execv qemu-x86_64");
        _exit(127);
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
                                        std::chrono::seconds(5),
                                        std::chrono::milliseconds(100));
        if (sock_fd_ < 0) {
            perror("connect to plugin socket");
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


    if (!writeWholeFile(kMemDump, data, n)) return false;
    char cmd[128];
    std::snprintf(cmd, sizeof(cmd), "set memory 0x%llx;0x%llx",
                  (unsigned long long)address, (unsigned long long)address + n);
    return sendCommandOnce(cmd, &ret);


    return 0;
}

int Emulator::ignoreMemory(uint64_t lowAddress, uint64_t highAddress) {
    (void)lowAddress; (void)highAddress;
    return 0;
}

std::shared_ptr<uint8_t> Emulator::getMemory(uint64_t address) {
    (void)address;
    return nullptr;
}

uint64_t Emulator::getRegister(std::string reg_name) {
    (void)reg_name;
    return 0;
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
    return sendCommandOnce("step " + std::to_string(steps), &ret);
    return 0;
}

std::string Emulator::disassembleInstruction(uint64_t address,
                                             std::shared_ptr<uint8_t> data, int n) {
    (void)address; (void)data; (void)n;
    return {};
}
