#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include "scallop.h"

/* public globals defined in plugin.c */
extern FILE *g_out;
extern char g_mem_path[256];
extern char g_reg_path[256];

/* request queue (single shared req; control thread enqueues, vCPU thread services) */
pthread_mutex_t g_req_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_req_cv = PTHREAD_COND_INITIALIZER;
req_t g_req = {.kind = REQ_NONE, .lo = 0, .hi = 0, .done = false, .ok = false};

/* Optional helpers */
static inline int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F')
        return 10 + (c - 'A');
    return -1;
}
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
static GByteArray *read_hex_file(const char *path, size_t limit)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    GByteArray *out = g_byte_array_new();
    int c1, c2;
    for (;;)
    {
        do
        {
            c1 = fgetc(f);
            if (c1 == EOF)
                goto done;
        } while (hexval(c1) < 0);
        do
        {
            c2 = fgetc(f);
            if (c2 == EOF)
                goto done;
        } while (hexval(c2) < 0);
        uint8_t b = (hexval(c1) << 4) | hexval(c2);
        g_byte_array_append(out, &b, 1);
        if (limit && out->len >= limit)
            break;
    }
done:
    fclose(f);
    return out;
}

/* vCPU init for reg APIs (use the typedef, not 'struct ...') */
void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    (void)vcpu_index;
    /* nothing persistent needed here in the simplified split */
}

/* Service one queued request (called from insn_exec_cb BEFORE gating) */
void service_pending_request(unsigned vcpu_index)
{
    (void)vcpu_index;

    // Take one request (if any)
    pthread_mutex_lock(&g_req_mu);
    req_t r = g_req; // snapshot
    if (r.kind == REQ_NONE)
    { // nothing to do
        pthread_mutex_unlock(&g_req_mu);
        return;
    }
    g_req.kind = REQ_NONE; // consume it
    pthread_mutex_unlock(&g_req_mu);

    bool ok = false;

    if (r.kind == REQ_GET_MEM)
    {
        size_t len = (r.hi >= r.lo) ? (size_t)(r.hi - r.lo + 1) : 0;
        if (len)
        {
            GByteArray *buf = g_byte_array_sized_new(len);
            if (qemu_plugin_read_memory_vaddr(r.lo, buf, len))
            {
                const char *path = *g_mem_path ? g_mem_path : "/tmp/branchmem.txt";
                FILE *f = fopen(path, "w");
                if (f)
                {
                    write_hex_dump(f, buf->data, buf->len);
                    fclose(f);
                    ok = true;
                }
            }
            g_byte_array_free(buf, TRUE);
        }
    }
    /* ---- GET_MEM ---- */
    if (r.kind == REQ_GET_MEM) {
        size_t len = (r.hi >= r.lo) ? (size_t)(r.hi - r.lo + 1) : 0;
        if (len) {
            GByteArray *buf = g_byte_array_sized_new(len);
            if (qemu_plugin_read_memory_vaddr(r.lo, buf, len)) {
                const char *path = *g_mem_path ? g_mem_path : "/tmp/memdump.txt";
                FILE *f = fopen(path, "w");
                if (f) {
                    for (size_t i = 0; i < buf->len; i++) {
                        fprintf(f, "%02x", buf->data[i]);
                        if ((i % 16) == 15) fputc('\n', f);
                        else fputc(' ', f);
                    }
                    if (buf->len && (buf->len % 16)) fputc('\n', f);
                    fclose(f);
                    ok = true;
                }
            }
            g_byte_array_free(buf, TRUE);
        }
    }


    else if (r.kind == REQ_SET_MEM)
    {
        size_t len = (r.hi >= r.lo) ? (size_t)(r.hi - r.lo + 1) : 0;
        if (len)
        {
            const char *path = *g_mem_path ? g_mem_path : "/tmp/branchmem.txt";
            GByteArray *src = read_hex_file(path, len);
            if (src && src->len)
                ok = qemu_plugin_write_memory_vaddr(r.lo, src);
            if (src)
                g_byte_array_free(src, TRUE);
        }
        /* === GET_REGS: dump all registers === */
    }
    else if (r.kind == REQ_GET_REGS)
    {
        GArray *regs = qemu_plugin_get_registers();
        if (regs)
        {
            const char *path = *g_reg_path ? g_reg_path : "/tmp/branchregs.txt";
            FILE *f = fopen(path, "w");
            if (f)
            {
                for (guint i = 0; i < regs->len; i++)
                {
                    qemu_plugin_reg_descriptor *d =
                        &g_array_index(regs, qemu_plugin_reg_descriptor, i);
                    if (!d->name)
                        continue;

                    /* read with a generous buffer; API returns how many bytes were read */
                    GByteArray *val = g_byte_array_sized_new(256);
                    g_byte_array_set_size(val, 256);
                    int got = qemu_plugin_read_register(d->handle, val);
                    if (got > 0)
                    {
                        fprintf(f, "%s=0x", d->name);
                        for (int j = got - 1; j >= 0; --j)
                            fprintf(f, "%02x", val->data[j]);
                        fputc('\n', f);
                    }
                    g_byte_array_free(val, TRUE);
                }
                fclose(f);
                ok = true;
            }
            g_array_free(regs, TRUE);
        }

        /* === SET_REGS: write from file === */
    }
    else if (r.kind == REQ_SET_REGS)
    {
        const char *path = *g_reg_path ? g_reg_path : "/tmp/branchregs.txt";
        FILE *f = fopen(path, "r");
        if (f)
        {
            GArray *regs = qemu_plugin_get_registers();
            if (regs)
            {
                char line[512];
                while (fgets(line, sizeof(line), f))
                {
                    char name[128], hex[384];
                    if (sscanf(line, "%127[^=]=%383s", name, hex) != 2)
                        continue;

                    /* locate descriptor by name */
                    qemu_plugin_reg_descriptor *d = NULL;
                    for (guint i = 0; i < regs->len; i++)
                    {
                        qemu_plugin_reg_descriptor *cur =
                            &g_array_index(regs, qemu_plugin_reg_descriptor, i);
                        if (cur->name && strcmp(cur->name, name) == 0)
                        {
                            d = cur;
                            break;
                        }
                    }
                    if (!d)
                        continue;

                    /* parse hex to bytes (little-endian in buffer, API expects target order) */
                    const char *p = (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) ? hex + 2 : hex;
                    size_t nhex = strnlen(p, sizeof(hex));
                    GByteArray *val = g_byte_array_sized_new((nhex + 1) / 2);
                    /* append low byte first */
                    for (ssize_t i = (ssize_t)nhex - 1; i >= 0;)
                    {
                        int lo = hexval((unsigned char)p[i--]);
                        if (lo < 0)
                            continue;
                        int hi = 0;
                        if (i >= 0)
                        {
                            int c = p[i--];
                            if ('0' <= c && c <= '9')
                                hi = c - '0';
                            else if ('a' <= c && c <= 'f')
                                hi = 10 + (c - 'a');
                            else if ('A' <= c && c <= 'F')
                                hi = 10 + (c - 'A');
                            else
                                hi = 0;
                        }
                        uint8_t b = (uint8_t)((hi << 4) | lo);
                        g_byte_array_append(val, &b, 1);
                    }

                    qemu_plugin_write_register(d->handle, val);
                    g_byte_array_free(val, TRUE);
                }
                g_array_free(regs, TRUE);
                ok = true;
            }
            fclose(f);
        }
        
    }

    done:
    pthread_mutex_lock(&g_req_mu);
    g_req.ok = ok;
    g_req.done = true;
    pthread_cond_broadcast(&g_req_cv);
    pthread_mutex_unlock(&g_req_mu);

}
