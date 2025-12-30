
# Scallop Shell - Disassembler, Debugger for Polymorphic code

<img width="520" height="520" alt="pixil-frame-0(2)" src="https://github.com/user-attachments/assets/499ccef4-afb0-4c02-888e-1045d65894cb" />

Alpha 1.0.0  

## Supported Platforms

Linux, possibly macOS  

## Motivation

GDB, pwndbg, Ghidra, IDA, are the current industry standards in reverse engineering. They are not well optimized for reverse engineering polymorphic binaries. The debuggers statically disassemble memory instead of displaying currently run instructions. They also aren't supported on Windows, and the windows debuggers are mostly GUI based. The decompilers completely break once you involve polymorphic code.

## To compile from source 

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

## Adding to path

If you want to add it to your command line, copy paste this into your .bashrc file (located in ~/)
```bash 
export PATH=$PATH:~/path/to/package
```
You can also just move it to your /usr/bin/. I don't see a downside to this. 
 
## Live Patching

One feature of Scallop Shell is live patching in the byte displays. If you want to change any of the bytes in the display, just click on the byte you want to change. Of course, the only values you can enter are 0-9 and A-F. Once you're done patching the bytes, hit enter and it'll save. You can hit Shift+Z to undo the edits you made UNTIL you step to the next instruction. Upon stepping, the live patcher will send a request to the emulator to modify the memory you changed. This then clears the history, so undoing is no longer possible. You can still edit it again of course.

## Notepad 

You can take notes on the Notepad tab about what you're working on. Ctrl+S to save. When you open Scallop Shell in the same directory again, it'll open your old notes back up.

## Debugging

You can run "step N", with N being the amount of instructions you want to step (this can be left blank for a default of 1). the "focus" command will filter out all memory outside of the low and high argument you specify (for example, "focus 0x400000 0x500000" will only output the instructions inside that range). Hitting enter will run the last command. 

Scallop Shell shows you the instruction right before it runs. So if you want to patch anything before it runs it'll let you. 

## Breakpoints 

Break anywhere you want by putting "break 0x" , followed by the instruction to break at. 
```
break 0x400360
```

## Instruction filtering

Currently, all instructions executed outside of the binary range are ignored. This leaves things like mmap() with executable memory unhandled by Scallop Shell. This will be fixed in a later version. 