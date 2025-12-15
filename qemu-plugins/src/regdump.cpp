#include "regdump.hpp"
#include "debug.hpp"

int regDump()
{
    if (scallopstate.vcpu_op[vcpu_current_thread_index].flags.load(std::memory_order_relaxed) 
        != VCPU_OP_DUMP_REGS) {
        return -1;
    }

    GArray *regs = qemu_plugin_get_registers();
    if (regs)
    {
        
        const char *path = *scallopstate.g_reg_path ? scallopstate.g_reg_path : "/tmp/branchregs.txt";
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
        }
        g_array_free(regs, TRUE);
    }

    return 0;
}
