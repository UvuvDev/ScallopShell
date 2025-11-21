#include "memorydump.hpp"
#include "debug.hpp"


/**
 * 
 */
static inline int hx(int c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return 10 + (c - 'a');
    if ('A' <= c && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}

/**
 * 
 */
static void write_hex_dump(FILE *f, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        fprintf(f, "%02x", p[i]);
        if ((i % 8) == 7)
            fputc('\n', f);
        else
            fputc(' ', f);
    }
    if (n && ((n - 1) % 8) != 7)
        fputc('\n', f);
}


/**
 * Not entirely sure what this does? Codex did this
 */
static bool try_chunked_memread(uint64_t base, size_t len, GByteArray *buf)
{
    const size_t chunk = 64;
    bool any = false;
    GByteArray *tmp = g_byte_array_sized_new(chunk);
    if (!tmp)
        return false;

    for (size_t off = 0; off < len; )
    {
        size_t want = chunk;
        if (want > len - off)
            want = len - off;

        g_byte_array_set_size(tmp, want);
        if (qemu_plugin_read_memory_vaddr(base + off, tmp, want))
        {
            memcpy(buf->data + off, tmp->data, want);
            any = true;
        }
        else
        {
            memset(buf->data + off, 0, want);
        }
        off += want;
    }

    g_byte_array_free(tmp, TRUE);
    return any;
}

int memDump(uint64_t address, int n, bool* ok) {

    // Verify validity
    if (address == 0) return 1;
    if (n == 0) return 1;


    // Make a GByteArray
    GByteArray *buf = g_byte_array_sized_new(n);
    if (!buf) // If failed to init, return fail
        return 1;

    // Set the size
    g_byte_array_set_size(buf, n);

    debug("memory request!!!\n");
    
    // Read the memory
    bool read_ok = qemu_plugin_read_memory_vaddr(address, buf, n);
    if (!read_ok)
    {
        debug("[mem] direct read 0x%016" PRIx64 " +0x%zx failed, retrying in chunks\n",
            address, n);
        read_ok = try_chunked_memread(address, n, buf);
    }

    // If the memory was read correctly:
    if (read_ok)
    {
        // Open the memdump file
        const char *path = *scallopstate.g_mem_path ? scallopstate.g_mem_path : "/tmp/memdump.txt";
        FILE *f = fopen(path, "w");
        if (f)
        {
            write_hex_dump(f, buf->data, buf->len);
            fclose(f);
            if (ok)
                *ok = true;
            debug("[mem] wrote %zu bytes from 0x%016" PRIx64 " to %s\n",
                buf->len, address, path);
        }
    }
    else
    {
        debug("[mem] unable to read memory at 0x%016" PRIx64 " len=0x%zx\n",
            address, n);
    }
    g_byte_array_free(buf, TRUE);

    return 0;

}
