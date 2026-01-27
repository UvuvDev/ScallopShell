#include "guihelpers.hpp"

std::string hex8ByteStr(uint64_t addr)
{
    std::ostringstream os;

    // First: create minimal hex with 0x
    std::ostringstream tmp;
    tmp << "0x" << std::uppercase << std::hex << addr;
    std::string core = tmp.str(); // "0x7FFFF565CB90"

    // Now right-align it in a fixed-width field
    constexpr int width = 2 + 2 * sizeof(void*); // e.g. 18 on 64-bit
    os << core; // os << std::setw(width) << std::setfill(' ') << core;

    return os.str();
}


std::string hex1ByteStr(uint8_t b)
{
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(b);
    return os.str();
}
int hexval(char c) {
      if ('0' <= c && c <= '9') return c - '0';
      if ('a' <= c && c <= 'f') return 10 + (c - 'a');
      if ('A' <= c && c <= 'F') return 10 + (c - 'A');
      return -1;
    }