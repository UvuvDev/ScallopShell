
TO DO SOON

- Tabbed window where memory display currently sits | DONE
    - Notepad | DONE
    - Memory display (name it) | DONE
    - Hex editor
    - Code byte editor / display

- Replace placeholder string in the CLI
- add borders to CLI when deselected
- start implementing commands like clear
    - add output window for commands
    - fix the CLI output bug when it fails a command to go to output window

LONG TERM INTEGRATION

- Abstract API for:
    - Getting code
    - Getting memory
    - Setting memory
    - Branch logging
    - Must be abstract - might implement both QEMU and Gem5, and maybe other things as well
- Make the Gem5 and QEMU APIs
- Add code disassembly window
- Finalize all commands 
- Start decompilation process
