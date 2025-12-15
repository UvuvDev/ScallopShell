#pragma once
#include <algorithm>

#include <stdio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>
#include <glib.h>
extern "C" {
    #include "qemu/qemu-plugin.h"
}
#include "gate.hpp"
#include "string"
#include "vector"
#include <memory>
#include <mutex>

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include "functional"
#include <memory> 

/**
 * This is the request type. We can handle requests in order of importance.
 */
enum class SCALLOP_REQUEST_TYPE {
    defaultReq,
    getMem,
    getReg,
    setMem,
    setReg,
    step,
    resume,
};

/**
 * Enum with commands.
 */
typedef enum {
    VCPU_OP_DUMP_REGS  = 1 << 1,
    VCPU_OP_SET_REGS   = 1 << 2,
    VCPU_OP_DUMP_MEM   = 1 << 1,
    VCPU_OP_SET_MEM    = 1 << 2,
    VCPU_OP_BREAKPOINT = 1 << 3,
} vcpu_operation_t;


/**
 * This is where pending executions from requests are stored.
 * There's 64 arguments for each bit in the flag. 64 possible
 * commands at the moment.
 */
struct vcpu_pending_ops {
    std::atomic_uint64_t flags;
    std::atomic<void*> arguments[64];

    vcpu_pending_ops() : flags(0) {
        for (int i = 0; i < 64; i++) {
            arguments[i].store(nullptr, std::memory_order_relaxed);
        }
    }
};

typedef struct {

    uint64_t mem_addr;
    int mem_size;
    uint8_t mem_data[4096];

} scallop_mem_arguments;

/**
 * Requests
 */
class scallop_request {

    std::string request; // The request saved by 
    SCALLOP_REQUEST_TYPE importance = SCALLOP_REQUEST_TYPE::defaultReq;

public:

    scallop_request(std::string _request, SCALLOP_REQUEST_TYPE _importance);

    std::string getRequest();
    SCALLOP_REQUEST_TYPE getImportance();
    

};

class ScallopSocket;

class ScallopState {
private:

    scallop_request highestPriorityReq(bool allow_qemu_ops);
    SCALLOP_REQUEST_TYPE classifyRequest(const std::string &request) const;

    mutable std::mutex requests_mutex_;
    std::unique_ptr<ScallopSocket> socket_;
    static inline qemu_plugin_id_t id = 0;
    GateManager gates; 
    
public:
    // File paths for output
    static char g_mem_path[256];
    static char g_reg_path[256];
    static FILE *g_out;
    static int g_log_disas;

    vcpu_pending_ops vcpu_op[MAX_VCPUS];

    std::vector<scallop_request> requests;

    void attachSocket(std::unique_ptr<ScallopSocket> socket);
    ScallopSocket *socket();
    const ScallopSocket *socket() const;

    void enqueueRawRequest(const std::string &request);
    int update(int vcpu = 0);

    GateManager& getGates();

    qemu_plugin_id_t getID();

    void setID(qemu_plugin_id_t id);

};

extern ScallopState scallopstate;

/**
 * For context: the purpose of this variable is to make sure that all 
 * threads have their own cpu index passed through to the functions they 
 * call. This is due to the restriction of arguments in functions further
 * down the call stack than the QEMU plugin callback. 
 */
extern int vcpu_current_thread_index; 