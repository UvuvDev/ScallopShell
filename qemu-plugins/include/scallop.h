#pragma once
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>
#include "qemu-plugin.h"


extern _Atomic unsigned long g_exec_ticks;
extern _Atomic unsigned long g_last_pc;

#define MAX_VCPUS 64
typedef struct {
  atomic_int running;     /* 1 = free-run, 0 = gated */
  atomic_long tokens;     /* when gated, how many instructions may run */
  pthread_mutex_t mu;
  pthread_cond_t  cv;
} gate_t;
extern gate_t g_gate[MAX_VCPUS];

/* ---- global config/state exposed across modules ---- */
extern atomic_int g_logging_enabled;
extern atomic_uintptr_t g_filter_lo, g_filter_hi;

/* CSV output file and options (owned by plugin.c) */
extern FILE *g_out;
extern int g_log_disas;

/* Control socket path (read-only outside control.c) */
extern char g_sock_path[256];

/* Optional file paths for mem/regs IO (set via args) */
extern char g_mem_path[256];
extern char g_reg_path[256];

/* ---- gating API (gate.c) ---- */
void gate_init_all(void);
void gate_pause_all(void);
void gate_resume_all(void);
void gate_give(unsigned vcpu, long n);
void gate_wait_if_in_range(unsigned vcpu, uint64_t pc);









// ---- request kinds
typedef enum {
    REQ_NONE = 0,
    REQ_GET_MEM,
    REQ_SET_MEM,
    REQ_GET_REGS,
    REQ_SET_REGS
} req_kind_t;

// ---- shared request object (owned by control/memregs together)
typedef struct {
    req_kind_t kind;     // what to do
    uint64_t   lo, hi;   // mem range (for GET/SET MEM)
    bool       done;     // set by vCPU side when finished
    bool       ok;       // success/failure of the operation
} req_t;

// ---- globals (defined in memregs.c)
extern pthread_mutex_t g_req_mu;
extern pthread_cond_t  g_req_cv;
extern req_t           g_req;

// ---- API from memregs.c
void vcpu_init_cb(qemu_plugin_id_t id, unsigned int vcpu_index);
void service_pending_request(unsigned int vcpu_index);

// ---- gating API from gate.c (already there)
void gate_pause_all(void);
void gate_resume_all(void);
void gate_give(unsigned vcpu, long n);
void gate_wait_if_in_range(unsigned vcpu, uint64_t pc);

// ---- control start/stop from control.c (already there)
int  control_start(void);
void control_stop(void);

// ---- logging hooks from logging.c
void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);

// ---- outs/memfile/regfile (owned in plugin.c)
extern FILE *g_out;
extern int   g_log_disas;
extern char  g_mem_path[256];
extern char  g_reg_path[256];

void dbg_init_once(void);

void dbg(const char *fmt, ...);