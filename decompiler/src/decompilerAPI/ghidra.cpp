#include "ghidra.hpp"
#include "main.hpp"

std::filesystem::path getProjectLocation(std::string projectSubdir) {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        return {};
    }
    return std::filesystem::path(home) / projectSubdir;
}

int runHeadless(const std::filesystem::path& ghidraHeadlessPath, const std::filesystem::path& elfPath, std::string projectName, std::string projectSubdir) {
    const auto projectLoc = getProjectLocation(projectSubdir);
    if (projectLoc.empty()) {
        std::cerr << "HOME not set; cannot locate project directory." << std::endl;
        return -1;
    }

    std::string cmd;
    cmd.reserve(512);
    cmd.append(ghidraHeadlessPath.string())
        .append(" ")
        .append(projectLoc.string())
        .append(" ")
        .append(projectName)
        .append(" -import ")
        .append(elfPath.string())
        .append(" -overwrite");

    return std::system(cmd.c_str());
}