--- ASM DUMP DESCRIPTION ---

Dump all instructions that are run by the program into a text file. You can run strings on it to isolate the instructions you want, or remove the ones you don't. This gets past self modifying techniques (like encrypting the instructions one at a time). 

Pass in your program as an argument to do a memory dump of it.

Abilities:

- Break when memory you want to watch is modified
- Check memory constantly to see if certain values are there (flags, shellcodes, etc)
- Break if anti debugging techniques are used and log where in the program they are
- Check every branch of the program and dump memory there too



