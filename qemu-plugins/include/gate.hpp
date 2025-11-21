#pragma once

#include <atomic>
#include <cstdint>
#include <pthread.h>

constexpr unsigned MAX_VCPUS = 64;

struct gate_t {
    std::atomic<int> running;   /* 1 = free-run, 0 = gated */
    std::atomic<long> tokens;   /* available instruction credits */
    pthread_mutex_t mu;
    pthread_cond_t cv;
};

class GateManager {
public:
    GateManager();

    void initAll();
    void pauseAll();
    void resumeAll();
    void stepIfNeeded(unsigned vcpu, uint64_t steps);
    void waitIfNeeded(unsigned vcpu, uint64_t pc);
    void inRange(uint64_t lowAddr, uint64_t highAddr);

    void give(unsigned vcpu, long tokens);

    bool loggingEnabled() const { return logging_enabled_.load(std::memory_order_relaxed) != 0; }
    void setLoggingEnabled(bool enable) { logging_enabled_.store(enable ? 1 : 0, std::memory_order_relaxed); }

protected:
    gate_t gates_[MAX_VCPUS];
    std::atomic<int> logging_enabled_;
    std::atomic<uintptr_t> filter_lo_;
    std::atomic<uintptr_t> filter_hi_;

    gate_t &gateFor(unsigned vcpu);
};
