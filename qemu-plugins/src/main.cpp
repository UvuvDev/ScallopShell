#include "main.hpp"
#include "debug.hpp"
#include "memorydump.hpp"
#include "regdump.hpp"
#include "socket.hpp"
#include "gate.hpp"
#include "disasm.hpp"
#include "setreg.hpp"

#include <atomic>
#include <dlfcn.h>
#include <thread>
#include <chrono>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
int vcpu_current_thread_index = 0;

char ScallopState::g_mem_path[256] = {0};
char ScallopState::g_reg_path[256] = {0};
FILE *ScallopState::g_out = nullptr;
int ScallopState::g_log_disas = 0;
SymbolResolver ScallopState::g_resolver;

ScallopState scallopstate;

namespace
{
    std::atomic<bool> request_worker_running{false};
    std::thread request_worker;

    /**
     * Check requests every 1 millisecond. Run once!!!!!!
     */
    void start_request_worker()
    {
        bool expected = false;
        if (!request_worker_running.compare_exchange_strong(expected, true))
        {
            return;
        }
        request_worker = std::thread([]()
                                     {
        while (request_worker_running.load(std::memory_order_relaxed)) {
            scallopstate.update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } });
    }

    /**
     * Kill the thread handling requests.
     */
    void stop_request_worker()
    {
        bool expected = true;
        if (!request_worker_running.compare_exchange_strong(expected, false))
        {
            return;
        }
        if (request_worker.joinable())
        {
            request_worker.join();
        }
    }
} // namespace

namespace
{
    /**
     * Normalizes all requests to be lowercase, no newlines or carriage returns,
     * keeps whitespace to max one character, and leaves non ASCII bytes untouched.
     */
    std::string normalize_request(const std::string &input)
    {
        std::string normalized;
        normalized.reserve(input.size());
        bool last_was_space = false;
        for (unsigned char c : input)
        {
            if (c == '\r' || c == '\n')
            {
                continue;
            }
            if (c == ' ' || c == '\t' || c == '\f')
            {
                if (!last_was_space && !normalized.empty())
                {
                    normalized.push_back(' ');
                }
                last_was_space = true;
            }
            else
            {

                if (c >= 'A' && c <= 'Z')
                {

                    // Convert uppercase to lowercase
                    // by adding 32
                    c += 32;
                }

                normalized.push_back(static_cast<char>((c)));
                last_was_space = false;
            }
        }
        if (!normalized.empty() && normalized.back() == ' ')
        {
            normalized.pop_back();
        }
        return normalized;
    }
} // namespace

/**
 * All the scallop_request definitions
 */
scallop_request::scallop_request(std::string _request, SCALLOP_REQUEST_TYPE _importance)
{
    request = _request;
    importance = _importance;
}
std::string scallop_request::getRequest()
{
    return request;
}
SCALLOP_REQUEST_TYPE scallop_request::getImportance()
{
    return importance;
}

/*=========================*/

/**
 * It orders requests by importance: if you do one thing before the other, information may be wrong. For example,
 * if you step before you set memory or set a register, it won't set at the assumed time,
 * making the program update the instruction AFTER it was supposed to. If you get mem or
 * get reg before you step, you won't have the updated memory and changes won't be made correctly.
 */
scallop_request ScallopState::highestPriorityReq(bool allow_qemu_ops)
{
    std::lock_guard<std::mutex> lock(requests_mutex_);

    if (requests.empty())
    {
        return scallop_request("", SCALLOP_REQUEST_TYPE::defaultReq);
    }

    std::size_t highestReqIndex = 0;
    for (std::size_t i = 1; i < requests.size(); i++)
    {
        if (requests.at(highestReqIndex).getImportance() < requests.at(i).getImportance())
        {
            highestReqIndex = i;
        }
    }

    scallop_request highestRequest = requests.at(highestReqIndex);
    requests.erase(requests.begin() +
                   static_cast<std::vector<scallop_request>::difference_type>(highestReqIndex));
    return highestRequest;
}

/**
 * Identify the type of request that was sent over, and assign the proper enum for it.
 * This keeps code organized and prevents unnecessary string comparison boilerplate
 */
SCALLOP_REQUEST_TYPE ScallopState::classifyRequest(const std::string &request) const
{
    std::string normalized = normalize_request(request);

    auto starts_with = [&normalized](const char *prefix)
    {
        return normalized.rfind(prefix, 0) == 0;
    };

    debug("req = %s\n", normalized.c_str());

    if (starts_with("get memory") || starts_with("memdump"))
    {
        return SCALLOP_REQUEST_TYPE::getMem;
    }
    if (starts_with("set memory") || starts_with("memset"))
    {
        return SCALLOP_REQUEST_TYPE::setMem;
    }
    if (starts_with("get registers") || starts_with("get regs") || normalized == "regs")
    {
        return SCALLOP_REQUEST_TYPE::getReg;
    }
    if (starts_with("get vcpu") || normalized == "vcpu" || normalized == "vcpus")
    {
        return SCALLOP_REQUEST_TYPE::getVcpu;
    }
    if (starts_with("set registers") || starts_with("regs set"))
    {
        return SCALLOP_REQUEST_TYPE::setReg;
    }
    if (starts_with("step"))
    {
        return SCALLOP_REQUEST_TYPE::step;
    }
    if (starts_with("resume"))
    {
        return SCALLOP_REQUEST_TYPE::resume;
    }
    if (starts_with("break"))
    {
        return SCALLOP_REQUEST_TYPE::breakpoint;
    }
    return SCALLOP_REQUEST_TYPE::defaultReq;
}

/**
 *
 */
void ScallopState::enqueueRawRequest(const std::string &request)
{
    const auto importance = classifyRequest(request);
    std::lock_guard<std::mutex> lock(requests_mutex_);
    requests.emplace_back(request, importance);
}

/**
 * Attach the TCP socket to the ScallopState
 */
void ScallopState::attachSocket(std::unique_ptr<ScallopSocket> socket)
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    socket_ = std::move(socket);
}

/**
 * @return ScallopSocket socket
 */
ScallopSocket *ScallopState::socket()
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    return socket_.get();
}

const ScallopSocket *ScallopState::socket() const
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    return socket_.get();
}

GateManager &ScallopState::getGates()
{
    return gates;
}

qemu_plugin_id_t ScallopState::getID()
{
    return id;
}

void ScallopState::setID(qemu_plugin_id_t id)
{
    this->id = id;
}

/**
 * This runs through the queue of requests that the front end made. It does it in order of
 * importance: if you do one thing before the other, information may be wrong. For example,
 * if you step before you set memory or set a register, it won't set at the assumed time,
 * making the program update the instruction AFTER it was supposed to. If you get mem or
 * get reg before you step, you won't have the updated memory and changes won't be made correctly.
 */
int ScallopState::update(int vcpu)
{
    //debug("at head of update\n");
    scallop_request req("", SCALLOP_REQUEST_TYPE::defaultReq); // Default initialize
    while ((req = highestPriorityReq(false)).getImportance() != SCALLOP_REQUEST_TYPE::defaultReq)
    {
        switch (req.getImportance())
        {
        case SCALLOP_REQUEST_TYPE::getMem:
        {
            uint64_t addr;
            int n;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
    
            // Read the request arguments from the req
            if (sscanf(req.getRequest().c_str(), "get memory 0x%llx %d %d %d", &addr, &n, &vcpu_id, &thread_id) != 4 &&
                sscanf(req.getRequest().c_str(), "get memory 0x%llx %d %d %63s", &addr, &n, &vcpu_id, thread_name) != 4)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            
            scallop_mem_arguments* memArgs;

            // If setting the flags and arguments doesn't succeed, continue
            if (setFlagAndInitArguments<scallop_mem_arguments>(vcpu_id, VCPU_OP_DUMP_MEM, &memArgs)) {
                //debug("fail");
                break;
            }
            
            // Define args 
            memArgs->mem_addr = addr;
            memArgs->mem_size = n;

            // Set the flags arguments to memArgs
            setArguments(vcpu_id, VCPU_OP_DUMP_MEM, memArgs);
            
            break;

        }
        case SCALLOP_REQUEST_TYPE::getReg:
        {
            int* throwaway;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "get regs %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get regs %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "get registers %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get registers %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "regs %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "regs %d %63s", &vcpu_id, thread_name) != 2)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            setFlagAndInitArguments<int>(vcpu_id, VCPU_OP_DUMP_REGS, &throwaway);
            break;
        }
        case SCALLOP_REQUEST_TYPE::getVcpu:
        {
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "get vcpu %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get vcpu %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "get vcpus %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "get vcpus %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpu %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpu %d %63s", &vcpu_id, thread_name) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpus %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "vcpus %d %63s", &vcpu_id, thread_name) != 2)
            {
                break;
            }
            (void)vcpu_id;
            (void)thread_id;
            (void)thread_name;
            const int vcpus = qemu_plugin_num_vcpus();
            constexpr int threads_per_vcpu = 1;
            const int total_threads = vcpus * threads_per_vcpu;
            char response[128];
            snprintf(response, sizeof(response),
                     "vcpu_info vcpus=%d threads_per_vcpu=%d total_threads=%d\n",
                     vcpus, threads_per_vcpu, total_threads);
            debug("%s\n", response);
            if (auto *sock = scallopstate.socket())
            {
                sock->sendLine(response);
            }
            break;
        }
        case SCALLOP_REQUEST_TYPE::setMem:
        {
            uint64_t addr;
            int n;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
    
            // Read the request arguments from the req
            if (sscanf(req.getRequest().c_str(), "set memory 0x%llx %d %d %d", &addr, &n, &vcpu_id, &thread_id) != 4 &&
                sscanf(req.getRequest().c_str(), "set memory 0x%llx %d %d %63s", &addr, &n, &vcpu_id, thread_name) != 4)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            
            scallop_mem_arguments* memArgs;

            // If setting the flags and arguments doesn't succeed, continue
            if (setFlagAndInitArguments<scallop_mem_arguments>(vcpu_id, VCPU_OP_SET_MEM, &memArgs)) {
                //debug("fail");
                break;
            }
            
            // Define args 
            memArgs->mem_addr = addr;
            memArgs->mem_size = n;


            // Set the flags arguments to memArgs
            setArguments(vcpu_id, VCPU_OP_SET_MEM, memArgs);
            
            break;
        }
        case SCALLOP_REQUEST_TYPE::setReg:
        {
            //vcpu_op[vcpu].flags |= vcpu_operation_t::VCPU_OP_SET_REGS;
            break;
        }
        case SCALLOP_REQUEST_TYPE::step:
        {
            int steps;
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "step %d %d %d", &steps, &vcpu_id, &thread_id) != 3 &&
                sscanf(req.getRequest().c_str(), "step %d %d %63s", &steps, &vcpu_id, thread_name) != 3)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;
            scallopstate.getGates().stepIfNeeded(vcpu_id, steps);
            break;
        }
        case SCALLOP_REQUEST_TYPE::resume:
        {
            int vcpu_id;
            int thread_id;
            char thread_name[64];
            if (sscanf(req.getRequest().c_str(), "resume %d %d", &vcpu_id, &thread_id) != 2 &&
                sscanf(req.getRequest().c_str(), "resume %d %63s", &vcpu_id, thread_name) != 2)
            {
                break;
            }
            (void)vcpu_id;
            (void)thread_id;
            (void)thread_name;
            scallopstate.getGates().resumeAll();
            break;
        }
        case SCALLOP_REQUEST_TYPE::breakpoint:
        {
            uint64_t addr;
            int vcpu_id;
            int thread_id;
            char thread_name[64];

            // Read the request arguments from the req
            if (sscanf(req.getRequest().c_str(), "break 0x%llx %d %d", &addr, &vcpu_id, &thread_id) != 3 &&
                sscanf(req.getRequest().c_str(), "break 0x%llx %d %63s", &addr, &vcpu_id, thread_name) != 3)
            {
                break;
            }
            (void)thread_id;
            (void)thread_name;

            debug("%s ...... parsed val = %llx", req.getRequest().c_str(), addr);
            scallopstate.getGates().addBreakpoint(addr, vcpu_id);
            break;
        }
        }
    }

    return 0;
}



int ScallopState::setArguments(int vcpu, vcpu_operation_t cmd, void* args) {
    vcpu_op[vcpu].arguments[std::countr_zero(static_cast<uint64_t>(cmd))] = args; 
    return 0;
}


int ScallopState::removeFlag(int vcpu, vcpu_operation_t cmd) {
    // FLAGS AND (FLAGS AND NOT CMD) = turning off only the inputted flag
    scallopstate.vcpu_op[vcpu].flags.store(scallopstate.vcpu_op[vcpu].flags.load(std::memory_order_relaxed) & (~cmd), std::memory_order_relaxed);
    return 0;
}

bool ScallopState::getIsFlagQueued(int vcpu, vcpu_operation_t cmd) {
    return (scallopstate.vcpu_op[vcpu].flags.load(std::memory_order_relaxed) & cmd) != cmd;
}

/**
 * Handle when the plugin is told to die.
 */
static void plugin_exit(qemu_plugin_id_t id, void *u)
{
    scallopstate.getGates().pauseAll();
    stop_request_worker();
    if (scallopstate.g_out && scallopstate.g_out != stderr)
    {
        fflush(scallopstate.g_out);
        fclose(scallopstate.g_out);
        scallopstate.g_out = NULL;
    }
}

/**
 * On initialization
 */
QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{

    (void)info;
    const char *outfile = NULL;

    scallopstate.setID(id);

    initDebug();
    debug("[install] pid=%ld\n", (long)getpid());

    for (int i = 0; i < argc; i++)
    {
        if (!strncmp(argv[i], "file=", 5))
            outfile = argv[i] + 5;
        else if (!strncmp(argv[i], "out=", 4))
            outfile = argv[i] + 4;
        else if (!strcmp(argv[i], "disas=1"))
            scallopstate.g_log_disas = 1;
        else if (!strncmp(argv[i], "memfile=", 8))
            snprintf(scallopstate.g_mem_path, sizeof(scallopstate.g_mem_path), "%s", argv[i] + 8);
        else if (!strncmp(argv[i], "regfile=", 8))
            snprintf(scallopstate.g_reg_path, sizeof(scallopstate.g_reg_path), "%s", argv[i] + 8);
    }
    if (!*scallopstate.g_mem_path) {
        std::filesystem::path path = std::filesystem::temp_directory_path() / "memdump.txt";
        snprintf(scallopstate.g_mem_path, sizeof(scallopstate.g_mem_path), path.c_str());
    }
    if (!*scallopstate.g_reg_path) {
        std::filesystem::path path = std::filesystem::temp_directory_path() / "regdump.txt";
        snprintf(scallopstate.g_reg_path, sizeof(scallopstate.g_reg_path), path.c_str());
    }

    scallopstate.g_out = fopen( (std::filesystem::temp_directory_path() / "branchlog.csv").c_str(), "w+");
    if (!scallopstate.g_out)
    {
        fprintf(stderr, "[branchlog] failed to open '%s'\n", outfile);
        scallopstate.g_out = stderr;
    }

    setvbuf(scallopstate.g_out, NULL, _IOLBF, 0);

    // Probably shouldnt hardcode this but whatever
    scallopstate.g_log_disas = 1;

    // Debug
    fprintf(stderr, "[branchlog] plugin install OK (file=%s mem=%s reg=%s)\n",
            outfile ? outfile : "(stderr)", scallopstate.g_mem_path, scallopstate.g_reg_path);
    fflush(stderr);

    fprintf(scallopstate.g_out, "pc,kind,branch_target,fallthrough,tb_vaddr,bytes%s,symbol\n", scallopstate.g_log_disas ? ",disas" : "");
    fflush(scallopstate.g_out);

    Dl_info soinfo{};
    if (dladdr((void *)&qemu_plugin_install, &soinfo) && soinfo.dli_fname)
    {
        fprintf(stderr, "[branchlog] using plugin %s\n", soinfo.dli_fname);
        fflush(stderr);
    }

    scallopstate.getGates().initAll();

    auto control_socket = std::make_unique<ScallopSocket>(scallopstate);
    if (!control_socket->start())
    {
        debug("CONTROL SOCKET FAILED!!!! ");
        fprintf(stderr, "[branchlog] WARNING: control socket failed\n");
    }
    else
    {
        debug("Server success! listening on port %u\n",
              static_cast<unsigned>(control_socket->port()));
        fprintf(stderr, "[branchlog] control socket listening on port %u\n",
                static_cast<unsigned>(control_socket->port()));
        scallopstate.attachSocket(std::move(control_socket));
        start_request_worker();
    }

    // qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
