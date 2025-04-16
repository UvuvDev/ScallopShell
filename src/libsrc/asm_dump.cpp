#include "asm_dump.hpp"

FILE* initFile(const char* name) {
    
    FILE* fptr = fopen(name, "w");

    // Create a string for write into the file
    char s[] = ".intel_syntax noprefix\n";
    
    // Wrtie the string into the file using fwrite
    int n = fwrite(s, sizeof(char), strlen(s), fptr);
    
    return fptr;

}

void saveInsnToFile(cs_insn* insn, FILE* file) {

    fwrite(insn->mnemonic, sizeof(char), strlen(insn->mnemonic), file);
    fwrite("\t", sizeof(char), 1, file);
    fwrite(insn->op_str, sizeof(char), strlen(insn->op_str), file);
    fwrite("\n", sizeof(char), 1, file);
}