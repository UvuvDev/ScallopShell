#include "gate.hpp"
#include "debug.hpp"

int GateManager::addBreakpoint(uint64_t address, gate_t& gate) {
    gate.breakpoints.insert({address, 1});
    return 0;
}

int GateManager::addBreakpoint(uint64_t address, int vcpu) {
    gate_t &gate = gateFor(vcpu);
    gate.breakpoints.insert({address, 1});
    debug("breakpoint added %d\n", gate.breakpoints[address]);
    return 0;
}

int GateManager::isBreakpoint(uint64_t address, gate_t& gate) {
    
    auto it = gate.breakpoints.find(address);
    if (it == gate.breakpoints.end())
        return false;

    return it->second;
}


int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::function<int()> func) {
    return 0;
}

int GateManager::runFunctionAtBreakpoint(int breakpoint, gate_t& gate, std::string scriptPath) {
    return 0;
}
