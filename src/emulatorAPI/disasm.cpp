#include "emulatorAPI.hpp"

static std::vector<InstructionInfo> instructionInfo;


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



std::string Emulator::disassembleInstruction(uint64_t address,
                                             std::shared_ptr<uint8_t> data, int n)
{
    (void)address;
    (void)data;
    (void)n;
    return {};
}

std::vector<InstructionInfo>* Emulator::getRunInstructions(
    int start_line,
    int n,
    bool* updated,
    int* total_lines_out
) {
    
    static std::filesystem::path kCsvPath = std::filesystem::temp_directory_path() / "branchlog.csv";

    static int cached_start = -1, cached_n = -1;
    static uintmax_t cached_size = 0;
    static std::time_t cached_mtime = 0;
    static int cached_total_lines = 0;

    // ---------- file state ----------
    std::error_code ec;
    auto sz = std::filesystem::file_size(kCsvPath, ec);
    std::time_t mt = 0;

    if (!ec) { 
        auto ft = std::filesystem::last_write_time(kCsvPath, ec);
        if (!ec) {
            auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                ft - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
            mt = std::chrono::system_clock::to_time_t(sctp);
        }
    }

    const bool file_unchanged =
        (cached_start == start_line && cached_n == n && sz == cached_size && mt == cached_mtime);

    if (file_unchanged) {
        if (updated) *updated = false;
        if (total_lines_out) *total_lines_out = cached_total_lines;
        return &instructionInfo;
    }

    // file changed or request changed
    if (updated) *updated = true;

    instructionInfo.clear();

    std::ifstream f(kCsvPath, std::ios::in | std::ios::binary);
    if (!f) {
        cached_start = start_line;
        cached_n = n;
        cached_size = sz;
        cached_mtime = mt;
        cached_total_lines = 0;
        if (total_lines_out) *total_lines_out = 0;
        return &instructionInfo;
    }

    // ---------- header handling ----------
    std::string line;

    bool first_line_is_data = false;
    std::streampos after_first = 0;

    if (std::getline(f, line)) {
        std::string t = trim(line);
        first_line_is_data = (t.size() >= 3 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X'));
        after_first = f.tellg();
    }

    // If first line was header: keep stream after it.
    // If first line was data: rewind so we include it in counting and paging.
    if (first_line_is_data) {
        f.clear();
        f.seekg(0, std::ios::beg);
    } else {
        // already consumed header; keep going
        // (we are currently positioned after first line)
    }

    // ---------- count + page in one pass ----------
    int data_index = 0;       // counts ONLY valid data rows
    int returned = 0;
    int total_data_rows = 0;

    while (std::getline(f, line)) {
        std::string s = trim(line);
        if (s.empty()) continue;

        auto cols = parse_csv(s);
        if (cols.size() < 7) continue; // minimum columns when symbol is present

        const std::string& c0 = cols[0];
        if (c0.size() < 3 || !(c0[0] == '0' && (c0[1] == 'x' || c0[1] == 'X')))
            continue; // not a data row

        // This is a data row
        total_data_rows++;

        // If it's inside the requested window, parse & store it
        if (data_index >= start_line && (n <= 0 || returned < n)) {
            uint64_t pc = parse_hex(cols[0]);
            std::string disType = trim(cols[1]);
            uint64_t bt = parse_hex(cols[2]);
            uint64_t ft = parse_hex(cols[3]);

            // CSV layout (when disassembly is enabled):
            // pc,kind,branch_target,fallthrough,tb_vaddr,bytes,disas,symbol
            // Disassembly column is optional, but bytes is always present.
            std::string dis;
            std::string symbol;
            if (cols.size() >= 8) {
                dis = trim(cols[6]);
                symbol = trim(cols[7]);
            } else {
                dis.clear();
                symbol = trim(cols.back());
            }

            if (disType.empty()) {
                // your fallback classify logic (unchanged)
                size_t i = 0;
                while (i < dis.size() && std::isspace((unsigned char)dis[i])) ++i;
                size_t j = i;
                while (j < dis.size() && !std::isspace((unsigned char)dis[j])) ++j;
                std::string m = dis.substr(i, j - i);
                for (char &c : m) c = (char)std::tolower((unsigned char)c);

                if (m == "ret" || m == "retq" || m == "retn" || m == "iret") disType = "ret";
                else if (m == "jmp" || m == "ljmp") disType = "jmp";
                else if (m == "call" || m == "callq" || m == "lcall") disType = "call";
                else if (!m.empty() && m[0] == 'j' && m != "jmp") disType = "cond";
                else disType = "other";
            }

            instructionInfo.emplace_back(std::move(dis), std::move(disType), std::move(symbol), pc, bt, ft, bt ? 1u : 0u);
            ++returned;
        }

        data_index++;

        // If we've already returned n lines AND we only care about total_lines for PageDown,
        // we still need to keep counting to end-of-file. So do NOT break.
    }

    // cache bookkeeping
    cached_start = start_line;
    cached_n = n;
    cached_size = sz;
    cached_mtime = mt;
    cached_total_lines = total_data_rows;

    if (total_lines_out) *total_lines_out = total_data_rows;
    return &instructionInfo;
}
