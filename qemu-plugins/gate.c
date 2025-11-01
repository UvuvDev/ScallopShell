#include <stdatomic.h>
#include <pthread.h>
#include "scallop.h"


gate_t g_gate[MAX_VCPUS];

atomic_int       g_logging_enabled = 1;
atomic_uintptr_t g_filter_lo = 0;
atomic_uintptr_t g_filter_hi = (uintptr_t)-1;

static inline int in_range(uint64_t pc) {
  uintptr_t lo = atomic_load_explicit(&g_filter_lo, memory_order_relaxed);
  uintptr_t hi = atomic_load_explicit(&g_filter_hi, memory_order_relaxed);
  return (pc >= lo && pc <= hi);
}

void gate_init_all(void){
  for (int i=0;i<MAX_VCPUS;i++){
    atomic_store(&g_gate[i].running, 0);
    atomic_store(&g_gate[i].tokens,  0);
    pthread_mutex_init(&g_gate[i].mu, NULL);
    pthread_cond_init(&g_gate[i].cv, NULL);
  }
}
void gate_pause_all(void){ for (int i=0;i<MAX_VCPUS;i++) atomic_store(&g_gate[i].running,0); }
void gate_resume_all(void){
  for (int i=0;i<MAX_VCPUS;i++){
    atomic_store(&g_gate[i].running,1);
    pthread_mutex_lock(&g_gate[i].mu);
    pthread_cond_broadcast(&g_gate[i].cv);
    pthread_mutex_unlock(&g_gate[i].mu);
  }
}
void gate_give(unsigned vcpu, long n){
  vcpu &= (MAX_VCPUS-1);
  gate_t *g = &g_gate[vcpu];
  pthread_mutex_lock(&g->mu);
  long old = atomic_load_explicit(&g->tokens, memory_order_relaxed);
  if (n>0) atomic_store_explicit(&g->tokens, old+n, memory_order_relaxed);
  pthread_cond_broadcast(&g->cv);
  pthread_mutex_unlock(&g->mu);
}
void gate_wait_if_in_range(unsigned vcpu, uint64_t pc){
  vcpu &= (MAX_VCPUS-1);
  gate_t *g = &g_gate[vcpu];
  if (atomic_load_explicit(&g->running, memory_order_relaxed)) return;
  if (!in_range(pc)) return; /* free-run outside range */
  pthread_mutex_lock(&g->mu);
  for(;;){
    if (atomic_load_explicit(&g->running, memory_order_relaxed)) break;
    long t = atomic_load_explicit(&g->tokens, memory_order_relaxed);
    if (t>0){ atomic_fetch_sub_explicit(&g->tokens,1,memory_order_relaxed); break; }
    pthread_cond_wait(&g->cv, &g->mu);
  }
  pthread_mutex_unlock(&g->mu);
}
