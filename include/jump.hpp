#include "core.hpp"

long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
    int cpu, int group_fd, unsigned long flags);

bool jumpOccurred(uint64_t *jmpAddrArg,
    uint64_t *stayAddrArg, pid_t child);

bool handleJumps(int cnt);