#include "core.hpp"


void assignOpcode(uint8_t *opcode, int firstHalf, int secondHalf)
{

    // Opcode array first half
    opcode[0] = (firstHalf & 0x00000000000000FF);
    opcode[1] = (firstHalf & 0x000000000000FF00) >> 0x8;
    opcode[2] = (firstHalf & 0x0000000000FF0000) >> 0x10;
    opcode[3] = (firstHalf & 0x00000000FF000000) >> 0x18;
    opcode[4] = (firstHalf & 0x000000FF00000000) >> 0x20;
    opcode[5] = (firstHalf & 0x0000FF0000000000) >> 0x28;
    opcode[6] = (firstHalf & 0x00FF000000000000) >> 0x30;
    opcode[7] = (firstHalf & 0xFF00000000000000) >> 0x38;

    // Opcode array second half
    opcode[8] = (secondHalf & 0x00000000000000FF);
    opcode[9] = (secondHalf & 0x000000000000FF00) >> 0x8;
    opcode[10] = (secondHalf & 0x0000000000FF0000) >> 0x10;
    opcode[11] = (secondHalf & 0x00000000FF000000) >> 0x18;
    opcode[12] = (secondHalf & 0x000000FF00000000) >> 0x20;
    opcode[13] = (secondHalf & 0x0000FF0000000000) >> 0x28;
    opcode[14] = (secondHalf & 0x00FF000000000000) >> 0x30;
    opcode[15] = (secondHalf & 0xFF00000000000000) >> 0x38;
}

void startupMsg()
{

    std::ifstream file("README.md"); // Open the file in text mode.
    if (!file.is_open())
    {
        std::cerr << "Error: Could not open README.md" << std::endl;
        return;
    }

    std::string line;
    // Read file line by line and output it to the console.
    while (std::getline(file, line))
    {
        std::cout << line << "\n";
    }

    file.close(); // Close the file.
}
