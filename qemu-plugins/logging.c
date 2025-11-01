#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "scallop.h"

FILE *g_out = NULL;
int   g_log_disas = 1;

_Atomic unsigned long g_exec_ticks = 0;
_Atomic unsigned long g_last_pc = 0;


static inline const char *safe_disas(struct qemu_plugin_insn *insn){
  const char *s = qemu_plugin_insn_disas(insn);
  return s ? s : "";
}
static inline uint64_t insn_size_or_zero(struct qemu_plugin_insn *insn){
  return qemu_plugin_insn_size(insn);
}
static const char *classify_insn(const char *d){
  if (!d) return "other";
  while (*d==' '||*d=='\t') d++;
  if (!*d) return "other";
  if (!strncmp(d,"jmp",3)) return "jmp";
  if (*d=='j') return "cond";
  if (!strncmp(d,"call",4)) return "call";
  if (!strncmp(d,"ret",3))  return "ret";
  return "other";
}
static int parse_imm_target(const char *d, uint64_t *out_target){
  if (!d) return 0;
  const char *p = strstr(d,"0x"); if (!p) return 0;
  uint64_t v=0;
  if (sscanf(p,"%lx",&v)==1){ *out_target=v; return 1; }
  if (sscanf(p,"%" SCNx64, out_target)==1) return 1;
  return 0;
}

struct exec_ctx {
  uint64_t pc, tb_vaddr, fallthrough, branch_target;
  const char *kind;
  const char *disas;
};

// new:
static void insn_exec_cb(unsigned int vcpu_index, void *udata)
{
    struct exec_ctx *ctx = (struct exec_ctx*)udata;

    // 1) service control requests (mem/regs)
    service_pending_request(vcpu_index);

    // 2) apply gating (may block)
    gate_wait_if_in_range(vcpu_index, ctx->pc);

    // 3) branch CSV logging (unchanged)
    if (!g_out) return;
    if (!atomic_load_explicit(&g_logging_enabled, memory_order_relaxed)) return;


    uintptr_t lo = atomic_load(&g_filter_lo), hi = atomic_load(&g_filter_hi);
    if (ctx->pc < lo || ctx->pc > hi) return;

    if (g_log_disas)
      fprintf(g_out,"0x%" PRIx64 ",%s,%s0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 ",\"%s\"\n",
        ctx->pc, ctx->kind, (ctx->branch_target?"":""), ctx->branch_target?ctx->branch_target:0,
        ctx->fallthrough, ctx->tb_vaddr, ctx->disas?ctx->disas:"");
    else
      fprintf(g_out,"0x%" PRIx64 ",%s,%s0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64 "\n",
        ctx->pc, ctx->kind, (ctx->branch_target?"":""), ctx->branch_target?ctx->branch_target:0,
        ctx->fallthrough, ctx->tb_vaddr);
}

void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb){
  uint64_t tb_va = qemu_plugin_tb_vaddr(tb);
  size_t n = qemu_plugin_tb_n_insns(tb);
  for (size_t i=0;i<n;i++){
    struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
    struct exec_ctx *ctx = (struct exec_ctx*)calloc(1,sizeof(*ctx));
    ctx->pc = qemu_plugin_insn_vaddr(insn);
    ctx->tb_vaddr = tb_va;
    const char *d = safe_disas(insn);
    ctx->disas = d;
    ctx->kind = classify_insn(d);
    uint64_t sz = insn_size_or_zero(insn);
    ctx->fallthrough = sz ? (ctx->pc + sz) : 0;
    uint64_t tgt=0;
    if (!strcmp(ctx->kind,"jmp")||!strcmp(ctx->kind,"cond")||!strcmp(ctx->kind,"call")){
      if (parse_imm_target(d,&tgt)) ctx->branch_target=tgt;
    }
    qemu_plugin_register_vcpu_insn_exec_cb(
      insn, insn_exec_cb, QEMU_PLUGIN_CB_RW_REGS, ctx);
  }
}
