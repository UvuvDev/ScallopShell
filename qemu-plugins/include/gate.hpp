#pragma once
#include <atomic>
#include <cstdint>
#include <pthread.h>
#include "functional"
#include "string"
#include "unordered_map"

constexpr unsigned MAX_VCPUS = 64;

struct gate_t {
    std::atomic<int> running;   /* 1 = free-run, 0 = gated */
    std::atomic<long> tokens;   /* available instruction credits */
    pthread_mutex_t mu;
    pthread_cond_t cv;
    std::unordered_map<uint64_t, int> breakpoints;
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

    /**
     * Add a breakpoint to the specified address. 
     * @param address Address to break at
     */
    int addBreakpoint(uint64_t address, gate_t& gate);

    /**
     * Add a breakpoint to the specified address. 
     * @param address Address to break at
     */
    int addBreakpoint(uint64_t address, int vcpu);

    /**
     * Checks if there's a breakpoint at the specified address
     */
    int isBreakpoint(uint64_t address, gate_t& gate);

    /**
     * Run a specific function when breakpoint is reached
     * @param breakpoint the breakpoint ID
     * @param func Function to be run
     */
    int runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::function<int()> func);

    /**
     * Run a specific Python script when breakpoint is reached
     * @param breakpoint the breakpoint ID
     * @param scriptPath Script to be run's filepath
     */
    int runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::string scriptPath);

protected:
    gate_t gates_[MAX_VCPUS];
    std::atomic<int> logging_enabled_;
    std::atomic<uintptr_t> filter_lo_;
    std::atomic<uintptr_t> filter_hi_;

    gate_t &gateFor(unsigned vcpu);
};
