
# Scallop Shell - Disassembler, Debugger for Polymorphic code

Newly rewritten, currently non-functional pending development. IF YOU ARE LOOKING FOR A FUNCTIONAL VERSION GO TO 948639a AUG 18 2025  

  
  
<img width="520" height="520" alt="pixil-frame-0(2)" src="https://github.com/user-attachments/assets/499ccef4-afb0-4c02-888e-1045d65894cb" />

# To compile from source 

First download the capstone package. WITHOUT THIS THIS WILL NOT FUNCTION. For me in Fedora, it'll be:
```bash
sudo dnf install capstone        # Just running the precompiled binary
sudo dnf install capstone-devel  # Compiling from source
```
But your specific install command may vary, check the documentation for YOUR OS / Distro. 

Then, run in the main project directory:
```bash 
chmod +x ./build.sh
./build.sh
```

This will compile it using CMake and do all the linking for you. 

# Adding to path

If you want to add it to your command line, copy paste this into your .bashrc file (located in ~/)
```bash 
export PATH=$PATH:~/path/to/package
```
You can also just move it to your /usr/bin/. I don't see a downside to this. 
 
## Importing "Symbols"

TBW

## LibC printing

Scallop Shell will tell you when $RIP is equal to a symbol from LibC and will tell you what that symbol is. This is very useful for readability. *Be aware that malware will often jump a few instructions ahead of the target symbol. If you believe it's doing this, you will have to run through LibC itself by commenting the continue statement in asm_dump.cpp through source code modification.* 

## Debugging

TBW
