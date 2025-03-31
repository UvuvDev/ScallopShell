--- ASM DUMP DESCRIPTION ---

Dump all instructions that are run by the program into a text file. You can run strings on it to isolate the instructions you want, or remove the ones you don't. This gets past self modifying techniques (like encrypting the instructions one at a time). 

Pass in your program as an argument to do a memory dump of it.

Abilities:

- Break when memory you want to watch is modified
- Check memory constantly to see if certain values are there (flags, shellcodes, etc)
- Break if anti debugging techniques are used and log where in the program they are
- Check every branch of the program and dump memory there too

# To compile 

First download the capstone package. WITHOUT THIS THIS WILL NOT FUNCTION.

Run this in the terminal:

g++ -g ./src/ptrace_ASM_dump.cpp -I./include -L./src/ -leventhandler -lcapstone -o god_rev_script

g++                             Compiler
-g                              Enable debug symbols
-$(find . -name "*.cpp")        Compile all files with .cpp
-I./include                     Path for include files
-L./src/                        Path for library files
-leventhandler                  Link the event handler library
-lcapstone                      Link the Capstone Library
-o god_rev_script               Name of the binary