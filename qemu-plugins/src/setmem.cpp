#include "setmem.hpp"
#include "debug.hpp"

int setMem() {
    
    // If the command isn't set to Dump Mem, exit. 
    if (scallopstate.getIsFlagQueued(vcpu_current_thread_index, VCPU_OP_SET_MEM)) {
        //return -1;
    }

    // Zero the flag so the request isn't requeued.
    scallopstate.removeFlag(vcpu_current_thread_index, VCPU_OP_SET_MEM);
    
    // Load the address, size N, etc. 
    scallop_mem_arguments* memDumpArgs;

    // If arguments fail to load, exit
    if (scallopstate.getArguments<scallop_mem_arguments>(vcpu_current_thread_index, VCPU_OP_SET_MEM, &memDumpArgs)) {
        debug("failed to load arguments");
        return 1;        
    }

    uint64_t address = memDumpArgs->mem_addr;
    int n = memDumpArgs->mem_size;

    // Verify address and size are not null
    if (address == 0)  {
        
        return 1;
    }
    if (n == 0) { 
        
        return 1;
    }

    // Make a GByteArray
    GByteArray *buf = g_byte_array_sized_new(n);
    if (!buf)  {// If failed to init, return fail
        
        return 1;
    }

    // Set the size
    g_byte_array_set_size(buf, n);


    // Open memdump
    const char *path = *scallopstate.g_mem_path ? scallopstate.g_mem_path : "/tmp/memdump.txt";
    FILE *f = fopen(path, "r");
    if (f)
    {   
        // Scan the whole file in byte by byte
        uint8_t byteFromFile = 0;
        while (fscanf(f, " %hhx", &byteFromFile) == 1) {
            g_byte_array_append(buf, &byteFromFile, 1);
        }
    }
    else
    {
        debug("Couldn't open \n");
    }    
    
    // Writeeee the memory
    bool write_ok = qemu_plugin_write_memory_vaddr(address, buf);
    if (!write_ok)
    {
        debug("write mem failed!!!\n");
    }

    g_byte_array_free(buf, TRUE);

    return 0;
}