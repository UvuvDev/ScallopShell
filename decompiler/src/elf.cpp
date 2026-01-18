#include "main.hpp"

namespace {
constexpr uint8_t  ELFCLASS64 = 2;
constexpr uint8_t  ELFDATA2LSB = 1;
constexpr uint8_t  EV_CURRENT = 1;
constexpr uint16_t ET_EXEC = 2;
constexpr uint16_t EM_X86_64 = 0x3E;
constexpr uint32_t PT_LOAD = 1;
constexpr uint32_t PF_X = 0x1;
constexpr uint32_t PF_W = 0x2;
constexpr uint32_t PF_R = 0x4;
constexpr uint32_t SHT_NULL = 0;
constexpr uint32_t SHT_PROGBITS = 1;
constexpr uint32_t SHT_STRTAB = 3;
constexpr uint64_t SHF_WRITE = 0x1;
constexpr uint64_t SHF_ALLOC = 0x2;
constexpr uint64_t SHF_EXECINSTR = 0x4;

constexpr size_t ELF64_EHDR_SIZE = 64;
constexpr size_t ELF64_PHDR_SIZE = 56;
constexpr size_t ELF64_SHDR_SIZE = 64;
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
    uint64_t entry,
    uint64_t dataStart,
    uint64_t dataEnd,
    const std::vector<ElfSymbol>* symbols) {
    if (image.empty()) {
        return false;
    }

    if (entry < base || entry >= base + image.size()) {
        return false;
    }

    const size_t phoff = ELF64_EHDR_SIZE;
    const size_t p_offset = align_up(ELF64_EHDR_SIZE + ELF64_PHDR_SIZE, ELF_ALIGN);
    const size_t text_offset = p_offset;
    const size_t image_size = image.size();

    const bool have_data = (dataEnd > dataStart &&
                            dataStart >= base &&
                            dataEnd <= base + image.size());
    const bool have_symtab = (symbols && !symbols->empty());

    const size_t text_size = have_data ? static_cast<size_t>(dataStart - base) : image_size;
    const size_t data_offset = have_data
        ? (p_offset + static_cast<size_t>(dataStart - base))
        : 0;
    const size_t data_size = have_data
        ? static_cast<size_t>(dataEnd - dataStart)
        : 0;

    const uint16_t idx_text = 1;
    const uint16_t idx_data = have_data ? 2 : 0;
    const uint16_t idx_symtab = have_symtab ? (have_data ? 3 : 2) : 0;
    const uint16_t idx_strtab = have_symtab ? (idx_symtab + 1) : 0;
    const uint16_t idx_shstrtab = have_symtab ? (idx_strtab + 1)
                                              : (have_data ? 3 : 2);
    const uint16_t shnum = static_cast<uint16_t>(idx_shstrtab + 1);

    std::string strtab;
    std::vector<uint8_t> symtab;
    if (have_symtab) {
        strtab.push_back('\0');
        const uint8_t STB_GLOBAL = 1;
        const uint8_t STT_FUNC = 2;
        const uint8_t STT_OBJECT = 1;

        auto add_sym = [&](uint32_t nameOff, uint8_t info, uint16_t shndx,
                           uint64_t value, uint64_t size) {
            const size_t off = symtab.size();
            symtab.resize(off + 24, 0);
            write_u32(symtab, off + 0, nameOff);
            symtab[off + 4] = info;
            symtab[off + 5] = 0;
            write_u16(symtab, off + 6, shndx);
            write_u64(symtab, off + 8, value);
            write_u64(symtab, off + 16, size);
        };

        add_sym(0, 0, 0, 0, 0); // null symbol

        for (const auto& sym : *symbols) {
            const uint32_t nameOff = static_cast<uint32_t>(strtab.size());
            strtab.append(sym.name);
            strtab.push_back('\0');
            const uint16_t shndx = (sym.isData && have_data) ? idx_data : idx_text;
            const uint8_t type = sym.isData ? STT_OBJECT : STT_FUNC;
            const uint8_t info = static_cast<uint8_t>((STB_GLOBAL << 4) | type);
            add_sym(nameOff, info, shndx, sym.addr, sym.size);
        }
    }

    std::string shstrtab;
    shstrtab.push_back('\0');
    const auto add_name = [&](const std::string& name) {
        size_t off = shstrtab.size();
        shstrtab.append(name);
        shstrtab.push_back('\0');
        return off;
    };

    const size_t shname_text = add_name(".text");
    const size_t shname_data = have_data ? add_name(".data") : 0;
    const size_t shname_symtab = have_symtab ? add_name(".symtab") : 0;
    const size_t shname_strtab = have_symtab ? add_name(".strtab") : 0;
    const size_t shname_shstrtab = add_name(".shstrtab");

    size_t cursor = text_offset + image_size;
    size_t strtab_offset = 0;
    size_t symtab_offset = 0;
    if (have_symtab) {
        strtab_offset = align_up(cursor, 8);
        cursor = strtab_offset + strtab.size();
        symtab_offset = align_up(cursor, 8);
        cursor = symtab_offset + symtab.size();
    }

    const size_t shstrtab_offset = align_up(cursor, 8);
    cursor = shstrtab_offset + shstrtab.size();
    const size_t shoff = align_up(cursor, 8);

    const size_t file_size = shoff + static_cast<size_t>(shnum) * ELF64_SHDR_SIZE;

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
    write_u64(file, 40, shoff);

    // e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx
    write_u32(file, 48, 0);
    write_u16(file, 52, static_cast<uint16_t>(ELF64_EHDR_SIZE));
    write_u16(file, 54, static_cast<uint16_t>(ELF64_PHDR_SIZE));
    write_u16(file, 56, 1);
    write_u16(file, 58, static_cast<uint16_t>(ELF64_SHDR_SIZE));
    write_u16(file, 60, shnum);
    write_u16(file, 62, idx_shstrtab);

    // Program header (single LOAD segment)
    const size_t ph = phoff;
    write_u32(file, ph + 0, PT_LOAD);
    uint32_t p_flags = PF_R | PF_X;
    if (have_data)
        p_flags |= PF_W;
    write_u32(file, ph + 4, p_flags);
    write_u64(file, ph + 8, p_offset);
    write_u64(file, ph + 16, base);
    write_u64(file, ph + 24, base);
    write_u64(file, ph + 32, static_cast<uint64_t>(image.size()));
    write_u64(file, ph + 40, static_cast<uint64_t>(image.size()));
    write_u64(file, ph + 48, ELF_ALIGN);

    std::copy(image.begin(), image.end(), file.begin() + static_cast<size_t>(text_offset));

    if (have_symtab) {
        std::copy(strtab.begin(), strtab.end(),
                  file.begin() + static_cast<size_t>(strtab_offset));
        std::copy(symtab.begin(), symtab.end(),
                  file.begin() + static_cast<size_t>(symtab_offset));
    }

    std::copy(shstrtab.begin(), shstrtab.end(),
              file.begin() + static_cast<size_t>(shstrtab_offset));

    const size_t sh_base = shoff;
    size_t sh_index = 0;

    // Section header 0: NULL (all zeros)
    sh_index++;

    // Section header: .text
    const size_t sh_text = sh_base + sh_index * ELF64_SHDR_SIZE;
    write_u32(file, sh_text + 0, static_cast<uint32_t>(shname_text));
    write_u32(file, sh_text + 4, SHT_PROGBITS);
    write_u64(file, sh_text + 8, SHF_ALLOC | SHF_EXECINSTR);
    write_u64(file, sh_text + 16, base);
    write_u64(file, sh_text + 24, text_offset);
    write_u64(file, sh_text + 32, text_size);
    write_u32(file, sh_text + 40, 0);
    write_u32(file, sh_text + 44, 0);
    write_u64(file, sh_text + 48, 16);
    write_u64(file, sh_text + 56, 0);
    sh_index++;

    // Section header: .data
    if (have_data) {
        const size_t sh_data = sh_base + sh_index * ELF64_SHDR_SIZE;
        write_u32(file, sh_data + 0, static_cast<uint32_t>(shname_data));
        write_u32(file, sh_data + 4, SHT_PROGBITS);
        write_u64(file, sh_data + 8, SHF_ALLOC | SHF_WRITE);
        write_u64(file, sh_data + 16, dataStart);
        write_u64(file, sh_data + 24, data_offset);
        write_u64(file, sh_data + 32, data_size);
        write_u32(file, sh_data + 40, 0);
        write_u32(file, sh_data + 44, 0);
        write_u64(file, sh_data + 48, 8);
        write_u64(file, sh_data + 56, 0);
        sh_index++;
    }

    // Section header: .symtab
    if (have_symtab) {
        const size_t sh_sym = sh_base + sh_index * ELF64_SHDR_SIZE;
        write_u32(file, sh_sym + 0, static_cast<uint32_t>(shname_symtab));
        write_u32(file, sh_sym + 4, 2); // SHT_SYMTAB
        write_u64(file, sh_sym + 8, 0);
        write_u64(file, sh_sym + 16, 0);
        write_u64(file, sh_sym + 24, symtab_offset);
        write_u64(file, sh_sym + 32, symtab.size());
        write_u32(file, sh_sym + 40, idx_strtab); // link to .strtab
        write_u32(file, sh_sym + 44, 1); // one local symbol
        write_u64(file, sh_sym + 48, 8);
        write_u64(file, sh_sym + 56, 24);
        sh_index++;

        const size_t sh_st = sh_base + sh_index * ELF64_SHDR_SIZE;
        write_u32(file, sh_st + 0, static_cast<uint32_t>(shname_strtab));
        write_u32(file, sh_st + 4, SHT_STRTAB);
        write_u64(file, sh_st + 8, 0);
        write_u64(file, sh_st + 16, 0);
        write_u64(file, sh_st + 24, strtab_offset);
        write_u64(file, sh_st + 32, strtab.size());
        write_u32(file, sh_st + 40, 0);
        write_u32(file, sh_st + 44, 0);
        write_u64(file, sh_st + 48, 1);
        write_u64(file, sh_st + 56, 0);
        sh_index++;
    }

    // Section header: .shstrtab
    const size_t sh_str = sh_base + sh_index * ELF64_SHDR_SIZE;
    write_u32(file, sh_str + 0, static_cast<uint32_t>(shname_shstrtab));
    write_u32(file, sh_str + 4, SHT_STRTAB);
    write_u64(file, sh_str + 8, 0);
    write_u64(file, sh_str + 16, 0);
    write_u64(file, sh_str + 24, shstrtab_offset);
    write_u64(file, sh_str + 32, shstrtab.size());
    write_u32(file, sh_str + 40, 0);
    write_u32(file, sh_str + 44, 0);
    write_u64(file, sh_str + 48, 1);
    write_u64(file, sh_str + 56, 0);

    std::ofstream out(outPath, std::ios::binary);
    if (!out) {
        return false;
    }
    out.write(reinterpret_cast<const char*>(file.data()), static_cast<std::streamsize>(file.size()));
    return static_cast<bool>(out);
}
