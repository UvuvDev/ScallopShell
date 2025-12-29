#include "gate.hpp"
#include "debug.hpp"


int GateManager::addBreakpoint(uint64_t address, int vcpu) {

    gate_t &gate = gateFor(vcpu);
    
    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = std::atomic_load(&gate.bp_vec);
    auto newv = std::make_shared<std::vector<uint64_t>>(oldv ? *oldv : std::vector<uint64_t>{});

    newv->push_back(address);
    std::sort(newv->begin(), newv->end());
    newv->erase(std::unique(newv->begin(), newv->end()), newv->end());

    std::atomic_store(&gate.bp_vec, std::shared_ptr<const std::vector<uint64_t>>(newv));

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::addBreakpoint(uint64_t address, gate_t& gate) {

    pthread_mutex_lock(&gate.bp_write_mu);

    auto oldv = std::atomic_load(&gate.bp_vec);
    auto newv = std::make_shared<std::vector<uint64_t>>(oldv ? *oldv : std::vector<uint64_t>{});

    newv->push_back(address);
    std::sort(newv->begin(), newv->end());
    newv->erase(std::unique(newv->begin(), newv->end()), newv->end());

    std::atomic_store(&gate.bp_vec, std::shared_ptr<const std::vector<uint64_t>>(newv));

    pthread_mutex_unlock(&gate.bp_write_mu);
    return 0;
}

int GateManager::isBreakpoint(uint64_t address, gate_t& gate) {
    auto v = std::atomic_load(&gate.bp_vec);
    if (!v || v->empty()) return 0;
    return std::binary_search(v->begin(), v->end(), address) ? 1 : 0;
}


int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::function<int()> func) {
    return 0;
}

int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::string scriptPath) {
    return 0;
}
