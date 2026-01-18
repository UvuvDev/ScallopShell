#include "main.hpp"

#include <cctype>
#include <stdexcept>

namespace {
std::string trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start])))
        ++start;
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1])))
        --end;
    return s.substr(start, end - start);
}
} // namespace

std::string readTargetTriple(const std::filesystem::path& infoPath) {
    std::ifstream in(infoPath);
    if (!in) {
        throw std::runtime_error("Failed to open file info: " + infoPath.string());
    }

    std::string line;
    while (std::getline(in, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
            continue;

        const size_t eq = trimmed.find('=');
        if (eq == std::string::npos)
            continue;

        const std::string key = trim(trimmed.substr(0, eq));
        const std::string val = trim(trimmed.substr(eq + 1));
        if (key == "target_triple" && !val.empty())
            return val;
    }

    throw std::runtime_error("target_triple missing in file info: " + infoPath.string());
}
