#include "main.hpp"

#include <cctype>
#include <fstream>
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

namespace {
std::string tripleFromElfHeader(const std::vector<uint8_t>& buf) {
    if (buf.size() < 20)
        throw std::runtime_error("ELF header too small");

    if (!(buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F'))
        throw std::runtime_error("Not an ELF file");

    const uint8_t ei_class = buf[4];
    const uint8_t ei_data = buf[5];

    if (ei_class != 1 && ei_class != 2)
        throw std::runtime_error("Unsupported ELF class");
    if (ei_data != 1 && ei_data != 2)
        throw std::runtime_error("Unsupported ELF endianness");

    const bool is_le = (ei_data == 1);
    const uint16_t e_machine = is_le
        ? static_cast<uint16_t>(buf[18] | (buf[19] << 8))
        : static_cast<uint16_t>((buf[18] << 8) | buf[19]);

    std::string arch = "unknown";
    switch (e_machine) {
        case 0x03: // EM_386
            arch = "i386";
            break;
        case 0x3E: // EM_X86_64
            arch = "x86_64";
            break;
        case 0x28: // EM_ARM
            arch = "arm";
            break;
        case 0xB7: // EM_AARCH64
            arch = "aarch64";
            break;
        case 0x08: // EM_MIPS
            arch = (ei_class == 2) ? "mips64" : "mips";
            break;
        case 0x14: // EM_PPC
            arch = "powerpc";
            break;
        case 0x15: // EM_PPC64
            arch = "powerpc64";
            break;
        case 0xF3: // EM_RISCV
            arch = (ei_class == 2) ? "riscv64" : "riscv32";
            break;
        case 0x16: // EM_S390
            arch = "s390x";
            break;
        default:
            break;
    }

    const std::string vendor = "unknown";
    const std::string os = "linux-gnu";
    return arch + "-" + vendor + "-" + os;
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

bool writeTargetTripleFromElf(
    const std::filesystem::path& elfPath,
    const std::filesystem::path& infoPath) {
    std::ifstream in(elfPath, std::ios::binary);
    if (!in) {
        std::cerr << "Failed to open ELF file: " << elfPath << std::endl;
        return false;
    }

    std::vector<uint8_t> header(64, 0);
    in.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (!in) {
        std::cerr << "Failed to read ELF header: " << elfPath << std::endl;
        return false;
    }

    std::string triple;
    try {
        triple = tripleFromElfHeader(header);
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << ": " << elfPath << std::endl;
        return false;
    }

    std::ofstream out(infoPath);
    if (!out) {
        std::cerr << "Failed to write file info: " << infoPath << std::endl;
        return false;
    }

    out << "# Scallop file info\n";
    out << "# Key=value pairs\n";
    out << "# target_triple is the LLVM target triple for the input binary\n\n";
    out << "target_triple=" << triple << "\n";
    return true;
}
