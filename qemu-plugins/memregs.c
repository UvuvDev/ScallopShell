#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <glib.h>
#include "scallop.h"

pthread_mutex_t g_req_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_req_cv = PTHREAD_COND_INITIALIZER;
req_t g_req = {0};

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
        } while (hx(c1) < 0);
        do
        {
            c2 = fgetc(f);
            if (c2 == EOF)
                goto done;
        } while (hx(c2) < 0);
        uint8_t b = (hx(c1) << 4) | hx(c2);
        g_byte_array_append(out, &b, 1);
        if (limit && out->len >= limit)
            break;
    }
done:
    fclose(f);
    return out;
}

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

void dumpMem(const req_t *req, bool *ok)
{
    if (!req)
        return;
    size_t len = (req->hi >= req->lo) ? (size_t)(req->hi - req->lo + 1) : 0;
    if (len == 0 || req->hi == 0 || req->lo == 0)
        return;

    GByteArray *buf = g_byte_array_sized_new(len);
    if (!buf)
        return;

    g_byte_array_set_size(buf, len);

    bool read_ok = qemu_plugin_read_memory_vaddr(req->lo, buf, len);
    if (!read_ok)
    {
        dbg("[mem] direct read 0x%016" PRIx64 " +0x%zx failed, retrying in chunks\n",
            req->lo, len);
        read_ok = try_chunked_memread(req->lo, len, buf);
    }

    if (read_ok)
    {
        const char *path = *g_mem_path ? g_mem_path : "/tmp/memdump.txt";
        FILE *f = fopen(path, "w");
        if (f)
        {
            write_hex_dump(f, buf->data, buf->len);
            fclose(f);
            if (ok)
                *ok = true;
            dbg("[mem] wrote %zu bytes from 0x%016" PRIx64 " to %s\n",
                buf->len, req->lo, path);
        }
    }
    else
    {
        dbg("[mem] unable to read memory at 0x%016" PRIx64 " len=0x%zx\n",
            req->lo, len);
    }
    g_byte_array_free(buf, TRUE);
}

void dumpReg(bool *ok)
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
                // Read into an empty GByteArray so QEMU sets the true size.
                GByteArray *val = g_byte_array_new();
                int got = qemu_plugin_read_register(d->handle, val);
                if (got > 0 && (guint)got == val->len)
                {
                    fprintf(f, "%s=0x", d->name);
                    for (int j = got - 1; j >= 0; j--)
                        fprintf(f, "%02x", val->data[j]);
                    fputc('\n', f);
                }
                g_byte_array_free(val, TRUE);
            }
            fflush(f);
            int fd = fileno(f);
            if (fd >= 0)
            {
                fsync(fd);
            }
            fclose(f);

            if (ok != NULL)
                *ok = true;
        }
        g_array_free(regs, TRUE);
    }
}

void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    (void)id;
    (void)vcpu_index;
    dumpReg(NULL);
}

void service_pending_request(unsigned vcpu_index)
{
    (void)vcpu_index;

    // take a snapshot of the request and clear it
    pthread_mutex_lock(&g_req_mu);
    req_t r = g_req;

    if (r.kind == REQ_NONE)
    {
        pthread_mutex_unlock(&g_req_mu);
        return;
    }
    g_req.kind = REQ_NONE;
    g_req.recredit = false;
    pthread_mutex_unlock(&g_req_mu);

    bool ok = false;

    if (r.kind == REQ_GET_MEM)
    {
        dumpMem(&r, &ok);
    }
    else if (r.kind == REQ_SET_MEM)
    {
        size_t len = (r.hi >= r.lo) ? (size_t)(r.hi - r.lo + 1) : 0;
        if (len)
        {
            const char *path = *g_mem_path ? g_mem_path : "/tmp/branchmem.txt";
            GByteArray *src = read_hex_file(path, len);
            if (src && src->len == len)
            {
                ok = qemu_plugin_write_memory_vaddr(r.lo, src);
            }
            if (src)
                g_byte_array_free(src, TRUE);
        }
    }
    else if (r.kind == REQ_GET_REGS)
    {
        dumpReg(&ok);
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

                    // find descriptor
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
                    if (!d || !d->name)
                        continue;

                    // Probe: how many bytes does QEMU expect for this reg?
                    int n_expect = 0;
                    {
                        GByteArray *probe = g_byte_array_sized_new(256);
                        g_byte_array_set_size(probe, 256);
                        n_expect = qemu_plugin_read_register(d->handle, probe);
                        g_byte_array_free(probe, TRUE);
                    }
                    if (n_expect <= 0)
                        continue; // unreadable or unknown size

                    // Parse hex (big-endian text) -> little-endian byte array of exactly n_expect bytes
                    const char *p = (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) ? hex + 2 : hex;
                    size_t nhex = strnlen(p, sizeof(hex));
                    GByteArray *val = g_byte_array_sized_new(n_expect);
                    g_byte_array_set_size(val, n_expect);
                    memset(val->data, 0, n_expect);

                    ssize_t wi = 0;
                    for (ssize_t i = (ssize_t)nhex - 1; i >= 0 && wi < n_expect;)
                    {
                        int lo = hx((unsigned char)p[i--]);
                        if (lo < 0)
                            continue;
                        int hi = 0;
                        if (i >= 0)
                        {
                            int c = p[i--];
                            hi = hx(c);
                            if (hi < 0)
                                hi = 0;
                        }
                        val->data[wi++] = (uint8_t)((hi << 4) | lo);
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

    // signal completion
    pthread_mutex_lock(&g_req_mu);
    g_req.ok = ok;
    g_req.done = true;
    pthread_cond_broadcast(&g_req_cv);
    pthread_mutex_unlock(&g_req_mu);

    if (r.recredit)
    {
        unsigned vcpu = vcpu_index & (MAX_VCPUS - 1);
        if (!atomic_load_explicit(&g_gate[vcpu].running, memory_order_relaxed))
        {
            gate_give(vcpu, 1);
        }
    }
}
