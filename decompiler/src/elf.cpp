#include "main.hpp"

namespace {
constexpr uint8_t  ELFCLASS64 = 2;
constexpr uint8_t  ELFDATA2LSB = 1;
constexpr uint8_t  EV_CURRENT = 1;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t EM_X86_64 = 0x3E;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PF_X = 0x1;
constexpr uint32_t PF_R = 0x4;

constexpr size_t ELF64_EHDR_SIZE = 64;
constexpr size_t ELF64_PHDR_SIZE = 56;
constexpr size_t ELF_ALIGN = 0x1000;

size_t align_up(size_t value, size_t alignment) {
    if (alignment == 0)
        return value;
    const size_t rem = value % alignment;
    return rem == 0 ? value : value + (alignment - rem);
}

void write_u16(std::vector<uint8_t>& buf, size_t off, uint16_t v) {
    buf[off + 0] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

void write_u32(std::vector<uint8_t>& buf, size_t off, uint32_t v) {
    buf[off + 0] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

void write_u64(std::vector<uint8_t>& buf, size_t off, uint64_t v) {
    write_u32(buf, off + 0, static_cast<uint32_t>(v & 0xFFFFFFFFu));
    write_u32(buf, off + 4, static_cast<uint32_t>((v >> 32) & 0xFFFFFFFFu));
}
} // namespace

bool writeElfX64LE(
    const std::filesystem::path& outPath,
    const std::vector<uint8_t>& image,
    uint64_t base,
    uint64_t entry) {
    if (image.empty()) {
        return false;
    }

    if (entry < base || entry >= base + image.size()) {
        return false;
    }

    const size_t phoff = ELF64_EHDR_SIZE;
    const size_t p_offset = align_up(ELF64_EHDR_SIZE + ELF64_PHDR_SIZE, ELF_ALIGN);
    const size_t file_size = p_offset + image.size();

    std::vector<uint8_t> file(file_size, 0x00);

    // e_ident
    file[0] = 0x7F;
    file[1] = 'E';
    file[2] = 'L';
    file[3] = 'F';
    file[4] = ELFCLASS64;
    file[5] = ELFDATA2LSB;
    file[6] = EV_CURRENT;
    file[7] = 0; // ELFOSABI_SYSV
    file[8] = 0; // ABI version

    // e_type, e_machine, e_version
    write_u16(file, 16, ET_EXEC);
    write_u16(file, 18, EM_X86_64);
    write_u32(file, 20, EV_CURRENT);

    // e_entry, e_phoff, e_shoff
    write_u64(file, 24, entry);
    write_u64(file, 32, phoff);
    write_u64(file, 40, 0); // no section headers

    // e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    write_u32(file, 48, 0);
    write_u16(file, 52, static_cast<uint16_t>(ELF64_EHDR_SIZE));
    write_u16(file, 54, static_cast<uint16_t>(ELF64_PHDR_SIZE));
    write_u16(file, 56, 1);
    write_u16(file, 58, 0);
    write_u16(file, 60, 0);
    write_u16(file, 62, 0);

    // Program header (single LOAD segment)
    const size_t ph = phoff;
    write_u32(file, ph + 0, PT_LOAD);
    write_u32(file, ph + 4, PF_R | PF_X);
    write_u64(file, ph + 8, p_offset);
    write_u64(file, ph + 16, base);
    write_u64(file, ph + 24, base);
    write_u64(file, ph + 32, static_cast<uint64_t>(image.size()));
    write_u64(file, ph + 40, static_cast<uint64_t>(image.size()));
    write_u64(file, ph + 48, ELF_ALIGN);

    std::copy(image.begin(), image.end(), file.begin() + static_cast<size_t>(p_offset));

    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    return static_cast<bool>(out);
}
