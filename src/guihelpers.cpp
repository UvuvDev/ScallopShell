#include "guihelpers.hpp"

std::string hex8ByteStr(uint64_t addr)
{
    std::ostringstream os;
    os << "0x" << std::uppercase << std::hex
       << std::setw(2 * sizeof(void *)) << std::setfill('0') << addr;
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