#include "emulatorAPI.hpp"

#ifdef _WIN32

#include "windows.h"

#else

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

#endif

/* Variables and helpers */
int child_pid_ = -1;
bool Emulator::isEmulating = false;

std::string pluginExtension() {
    #ifdef _WIN32 
        return ".dll";
    #else
        return ".so";
    #endif

}

std::string executableExtension() {
    #ifdef _WIN32 
        return ".exe";
    #else
        return "";
    #endif

}

bool Emulator::getIsEmulating()
{
    return isEmulating;
}

#ifdef _WIN32
int Emulator::startEmulation(const std::string &executablePathArg)
{
    return 1;
}
#else
int Emulator::startEmulation(const std::string &executablePathArg, const std::string& arch, bool system)
{
    static std::string executablePath = executablePathArg; // Path to the executable being debugged
    static std::string qemuArch = arch; // Architecture
    static bool isSystem = system; // Is system emulation

    // If there's a new binary then replace the executable path
    if (executablePathArg != "")
    {
        executablePath = executablePathArg;
    }
    if (arch != "") {
        qemuArch = arch;
    }


    // Find the QEMU binary to use on the target binary
    std::filesystem::path qemuPath = ::getenv("SCALLOP_QEMU_BUILD") ? ::getenv("SCALLOP_QEMU_BUILD") : "";
    qemuPath = qemuPath / "qemu-";
    qemuPath += (isSystem ? "system-" : "");
    qemuPath += qemuArch;
    qemuPath += (executableExtension());

    // Outputs for QEMU Plugin
    std::filesystem::path currentWorkingDir = std::filesystem::current_path();
    std::filesystem::path qemuTraceLog = currentWorkingDir;
    std::filesystem::path pluginPath = ::getenv("SCALLOP_QEMU_PLUGIN") ? ::getenv("SCALLOP_QEMU_PLUGIN") : currentWorkingDir / "qemu-plugins";
    std::filesystem::path csvPath = std::filesystem::temp_directory_path() / "branchlog.csv";

    qemuTraceLog = qemuTraceLog / "qemu.log";

    // ---- build argv: qemu -d plugin -D <log> -plugin <.so> -- <target> ----
    std::vector<std::string> args_str = {
        qemuPath.string(),
        "-d", "plugin",
        "-D", qemuTraceLog.string(),
        "-plugin", pluginPath.string(),
        "--",
        executablePath};

    // Put everything in argv to prepare it for qemu
    std::vector<char *> argv;
    argv.reserve(args_str.size() + 1);
    for (auto &s : args_str)
    {
        argv.push_back(const_cast<char *>(s.c_str()));
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
#endif