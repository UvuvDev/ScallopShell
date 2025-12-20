#include "gate.hpp"
#include "debug.hpp"

#include <algorithm>

GateManager::GateManager()
    : logging_enabled_(1),
      filter_lo_(0),
      filter_hi_(static_cast<uintptr_t>(-1)) {
    for (auto &gate : gates_) {
        gate.running.store(1, std::memory_order_relaxed);
        gate.tokens.store(0, std::memory_order_relaxed);
        pthread_mutex_init(&gate.mu, nullptr);
        pthread_cond_init(&gate.cv, nullptr);
    }
}

gate_t &GateManager::gateFor(unsigned vcpu) {
    return gates_[vcpu & (MAX_VCPUS - 1)];
}

void GateManager::initAll() {
    for (auto &gate : gates_) {
        gate.running.store(0, std::memory_order_relaxed);
        gate.tokens.store(0, std::memory_order_relaxed);
    }
}

void GateManager::pauseAll() {
    for (auto &gate : gates_) {
        gate.running.store(0, std::memory_order_relaxed);
    }
}

void GateManager::resumeAll() {
    for (auto &gate : gates_) {
        gate.running.store(1, std::memory_order_relaxed);
        pthread_mutex_lock(&gate.mu);
        pthread_cond_broadcast(&gate.cv);
        pthread_mutex_unlock(&gate.mu);
    }
}

void GateManager::give(unsigned vcpu, long tokens) {
    if (tokens <= 0) {
        return;
    }
    gate_t &gate = gateFor(vcpu);
    pthread_mutex_lock(&gate.mu);
    long current = gate.tokens.load(std::memory_order_relaxed);
    gate.tokens.store(current + tokens, std::memory_order_relaxed);
    pthread_cond_broadcast(&gate.cv);
    pthread_mutex_unlock(&gate.mu);
}

void GateManager::stepIfNeeded(unsigned vcpu, uint64_t steps) {
    if (steps == 0) {
        steps = 1;
    }
    pauseAll();
    give(vcpu, static_cast<long>(steps));
}

void GateManager::waitIfNeeded(unsigned vcpu, uint64_t pc) {

    debug("\n\n\nWAITING AT GATE!!!\n");

    gate_t &gate = gateFor(vcpu);

    if (gate.running.load(std::memory_order_relaxed)) {
        debug("Gate running: EXITING\n\n\n");
        return;
    }

    auto lo = filter_lo_.load(std::memory_order_relaxed);
    auto hi = filter_hi_.load(std::memory_order_relaxed);
    if (pc < lo || pc > hi) {
        debug("outside of filter range: EXITING\n\n\n");
        return;
    }

    debug("thread mutex locking... ");
    pthread_mutex_lock(&gate.mu);
    debug("thread mutex locked.\n ");

    for (;;) {
        debug("tick +1  ");
        if (gate.running.load(std::memory_order_relaxed)) {
            break;
        }
        long tokens = gate.tokens.load(std::memory_order_relaxed);
        if (tokens > 0) {
            gate.tokens.fetch_sub(1, std::memory_order_relaxed);
            break;
        }
        pthread_cond_wait(&gate.cv, &gate.mu);
    }
    debug("unlocking mutex...\n");
    pthread_mutex_unlock(&gate.mu);
    debug("EXITING GATE!!!\n\n\n");
}

void GateManager::inRange(uint64_t lowAddr, uint64_t highAddr) {
    if (highAddr < lowAddr) {
        std::swap(lowAddr, highAddr);
    }
    filter_lo_.store(static_cast<uintptr_t>(lowAddr), std::memory_order_relaxed);
    filter_hi_.store(static_cast<uintptr_t>(highAddr), std::memory_order_relaxed);
}
