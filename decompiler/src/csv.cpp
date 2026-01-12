#include "csv.hpp"


// --- helpers ---
static inline bool is_blank_line(const std::string& s) {
    for (char c : s) if (!std::isspace(static_cast<unsigned char>(c))) return false;
    return true;
}

// Basic CSV splitter that supports:
// - quoted fields with commas inside
// - escaped quotes inside quotes ("")
static std::vector<std::string> split_csv_line(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool in_quotes = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        if (in_quotes) {
            if (c == '"') {
                // Escaped quote?
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i; // consume second quote
                } else {
                    in_quotes = false; // end quote
                }
            } else {
                cur.push_back(c);
            }
        } else {
            if (c == '"') {
                in_quotes = true;
            } else if (c == ',') {
                out.push_back(cur);
                cur.clear();
            } else if (c == '\r' || c == '\n') {
                // ignore line endings
            } else {
                cur.push_back(c);
            }
        }
    }
    out.push_back(cur);
    return out;
}

static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> out;
    if (hex.empty()) return out;

    // Allow optional 0x prefix (just in case)
    size_t start = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
        start = 2;

    const size_t n = hex.size() - start;
    if (n % 2 != 0) {
        throw std::runtime_error("bytes hex string has odd length");
    }

    out.reserve(n / 2);
    for (size_t i = 0; i < n; i += 2) {
        const std::string byte_str = hex.substr(start + i, 2);
        uint8_t b = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        out.push_back(b);
    }
    return out;
}

// Returns:
//  0  = parsed OK
//  1  = header/skip line
// -1  = parse error
int parseLine(std::string csvLine, instructionData& insn) {
    try {
        if (csvLine.empty() || is_blank_line(csvLine))
            return 1;

        // Skip header
        // (works even if there's whitespace before/after)
        if (csvLine.rfind("pc,kind,", 0) == 0 || csvLine.rfind("pc,kind", 0) == 0)
            return 1;

        auto fields = split_csv_line(csvLine);

        // Expect at least:
        // 0 pc
        // 1 kind
        // 2 branch_target
        // 3 fallthrough
        // 4 tb_vaddr
        // 5 bytes
        // 6 disas
        // 7 symbol
        if (fields.size() < 8)
            return -1;

        insn.pc                 = std::stoull(fields[0], nullptr, 0);
        insn.branchTarget       = std::stoull(fields[2], nullptr, 0);
        insn.fallthroughAddr    = std::stoull(fields[3], nullptr, 0);
        insn.translatedBlockBase= std::stoull(fields[4], nullptr, 0);

        insn.bytes              = hex_to_bytes(fields[5]);
        insn.kind               = fields[1];
        insn.disassembly        = fields[6];
        insn.symbol             = fields[7];

        return 0;
    } catch (...) {
        return -1;
    }
}
