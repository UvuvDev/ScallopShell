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

g++ -g $(find . -name "*.cpp") -I./include -L./src/ -leventhandler -lcapstone -o ScallopShell

g++                             Compiler
-g                              Enable debug symbols
-$(find . -name "*.cpp")        Compile all files with .cpp
-I./include                     Path for include files
-L./src/                        Path for library files
-leventhandler                  Link the event handler library
-lcapstone                      Link the Capstone Library
-o ScallopShell               Name of the binary

If you want to add it to your command line, copy paste this into your .bashrc file (located in ~/)

export PATH=$PATH:~/path/to/package
# Importing "Symbols"

You can import symbols for certain addresses. These will be labeled differently than stripped instructions. The more symbols you have the slower the program becomes but that's okay for some extra readability! 

- b (for breakpoint)
- s (for symbol)

You have to make a .txt file containing the following format and feed it as a second argument:

......... = one space

Address (in hex).........(NO SPACES AT ALL, max 30 chars)Description..................Symbol_Type

DO NOT HAVE SPACES IN THE DESCRIPTION. I am using scanf("%p %s %c") it will break the entire code. 

If you make the Address 0xF0, it'll allow you to break on every call of the instruction mnemonic (which you use the description for). You still have to write a symbol type, I just use "b" since it's a breakpoint.