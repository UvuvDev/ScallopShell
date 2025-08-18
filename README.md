
--- ASM DUMP DESCRIPTION ---

Dump all instructions that are run by the program into a text file. You can run strings on it to isolate the instructions you want, or remove the ones you don't. This gets past self modifying techniques (like encrypting the instructions one at a time). 

Pass in your program as an argument to do a memory dump of it.

Current Functionality:

- Disassemble instruction by instruction
- Mass comment code via "memory maps"
- Filter LibC and ld.so code
- Breakpoints
- GDB-like CLI
- Backtracing
- Assembly dumping into a file
- Examining memory/registers

Features in Development:

- Jump tracking (a more general backtrace)
- Watchpoints
- Automated string/flag memory searching
- ANGR integration

# To compile from source 

First download the capstone package. WITHOUT THIS THIS WILL NOT FUNCTION. For me in Fedora, it'll be:
```bash
sudo dnf install capstone        # Just running the precompiled binary
sudo dnf install capstone-devel  # Compiling from source
```
But your specific install may vary, check the documentation.

Run this in the terminal: 

g++ -g $(find . -name "*.cpp") -I./include -L./src/ -leventhandler -lcapstone -o scallop

g++                             Compiler
-g                              Enable debug symbols
-$(find . -name "*.cpp")        Compile all files with .cpp
-I./include                     Path for include files
-L./src/                        Path for library files
-leventhandler                  Link the event handler library
-lcapstone                      Link the Capstone Library
-o scallop               Name of the binary

If you want to add it to your command line, copy paste this into your .bashrc file (located in ~/)

export PATH=$PATH:~/path/to/package
## Importing "Symbols"

You can import symbols for certain addresses. These will be labeled differently than stripped instructions. The more symbols you have the slower the program becomes but that's okay for some extra readability! 

- b (for breakpoint)
- s (for symbol)
- m (for map)
- l (for loop)

You have to make a .txt file containing the following format and feed it as a second argument:

......... = one space

Address (in hex).........(NO SPACES AT ALL, max 30 chars)Description..................Symbol_Type

DO NOT HAVE SPACES IN THE DESCRIPTION. I am using scanf("%p %s %c") it will break the entire code. 

If you make the Address 0xF0, it'll allow you to break on every call of the instruction mnemonic (which you use the description for). You still have to write a symbol type, I just use "b" since it's a breakpoint.

Special cases are for "m" and "l", they have extra arguments. 

- For M, you give one extra address after the type which will create a range of addresses that will be commented during runtime

- For L, you give an extra address AND a number specifying how many times you want to display this loop. Useful for when you have a loop repeating hundreds or thousands of times (like encrypting). 0 means it will never print, -1 will make it always print, and anything above 0 will be valid. Otherwise looks like a memory map.

## LibC printing

Scallop Shell will tell you when $RIP is equal to a symbol from LibC and will tell you what that symbol is. This is very useful for readability. *Be aware that malware will often jump a few instructions ahead of the target symbol. If you believe it's doing this, you will have to run through LibC itself by commenting the continue statement in asm_dump.cpp through source code modification.* 

## Debugging

Use memory maps, breakpoints, and symbols, and also use the "reg" and "flag" commands to print the values of registers and the flags.
