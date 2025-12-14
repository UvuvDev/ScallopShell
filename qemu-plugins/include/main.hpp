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

    GateManager gates;
    
public:

    std::atomic<uint64_t> current_pc_{0};

    // File paths for output
    static char g_mem_path[256];
    static char g_reg_path[256];
    static FILE *g_out;
    static int g_log_disas;

    std::vector<scallop_request> requests;

    void attachSocket(std::unique_ptr<ScallopSocket> socket);
    ScallopSocket *socket();
    const ScallopSocket *socket() const;

    void enqueueRawRequest(const std::string &request);
    int update(bool allow_qemu_ops = true);

    GateManager& getGates();

};

extern ScallopState scallopstate;
