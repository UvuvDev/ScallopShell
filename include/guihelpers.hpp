#pragma once
#include "string"
#include "cstdint"
#include "vector"
#include "iomanip"

std::string hex8ByteStr(uint64_t addr);
std::string hex1ByteStr(uint8_t b);
int hexval(char c);