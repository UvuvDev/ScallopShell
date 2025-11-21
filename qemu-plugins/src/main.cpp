#include "main.hpp"
#include "debug.hpp"
#include "memorydump.hpp"
#include "regdump.hpp"
#include "socket.hpp"
#include "gate.hpp"
#include "disasm.hpp"

#include <atomic>
#include <dlfcn.h>
#include <thread>
#include <chrono>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

char ScallopState::g_mem_path[256] = {0};
char ScallopState::g_reg_path[256] = {0};
FILE *ScallopState::g_out = nullptr;
int ScallopState::g_log_disas = 0;

ScallopState scallopstate;

namespace {
std::atomic<bool> request_worker_running{false};
std::thread request_worker;

void start_request_worker() {
    bool expected = false;
    if (!request_worker_running.compare_exchange_strong(expected, true)) {
        return;
    }
    request_worker = std::thread([]() {
        while (request_worker_running.load(std::memory_order_relaxed)) {
            scallopstate.update();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });
}

void stop_request_worker() {
    bool expected = true;
    if (!request_worker_running.compare_exchange_strong(expected, false)) {
        return;
    }
    if (request_worker.joinable()) {
        request_worker.join();
    }
}
} // namespace

namespace
{
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

scallop_request ScallopState::highestPriorityReq()
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

SCALLOP_REQUEST_TYPE ScallopState::classifyRequest(const std::string &request) const
{
    std::string normalized = normalize_request(request);

    auto starts_with = [&normalized](const char *prefix)
    {
        return normalized.rfind(prefix, 0) == 0;
    };

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
    return SCALLOP_REQUEST_TYPE::defaultReq;
}

void ScallopState::enqueueRawRequest(const std::string &request)
{
    const auto importance = classifyRequest(request);
    std::lock_guard<std::mutex> lock(requests_mutex_);
    requests.emplace_back(request, importance);
}

void ScallopState::attachSocket(std::unique_ptr<ScallopSocket> socket)
{
    std::lock_guard<std::mutex> lock(requests_mutex_);
    socket_ = std::move(socket);
}

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

int ScallopState::update()
{
    scallop_request req("", SCALLOP_REQUEST_TYPE::defaultReq);
    while ((req = highestPriorityReq()).getImportance() != SCALLOP_REQUEST_TYPE::defaultReq)
    {
        bool ok;
        switch (req.getImportance())
        {
        case SCALLOP_REQUEST_TYPE::getMem:
            uint64_t addr;
            int n;
            sscanf(req.getRequest().c_str(), "get memory 0x%llx %d", &addr, &n);
            memDump(addr, n, &ok);
            break;
        case SCALLOP_REQUEST_TYPE::getReg:
            regDump(&ok);
            break;
        case SCALLOP_REQUEST_TYPE::setMem:
            break;
        case SCALLOP_REQUEST_TYPE::setReg:
            break;
        case SCALLOP_REQUEST_TYPE::step:
            int steps;
            sscanf(req.getRequest().c_str(), "step %d", &steps);
            scallopstate.getGates().stepIfNeeded(0, steps);
            break;
        case SCALLOP_REQUEST_TYPE::resume:
            scallopstate.getGates().resumeAll();
            break;
        }
    }

    return 0;
}

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

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv)
{

    (void)info;
    const char *outfile = NULL;

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
    if (!*scallopstate.g_mem_path)
        snprintf(scallopstate.g_mem_path, sizeof(scallopstate.g_mem_path), "/tmp/memdump.txt");
    if (!*scallopstate.g_reg_path)
        snprintf(scallopstate.g_reg_path, sizeof(scallopstate.g_reg_path), "/tmp/regdump.txt");

    
    scallopstate.g_out = fopen("/tmp/branchlog.csv", "w+");
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

    fprintf(scallopstate.g_out, "pc,kind,branch_target,fallthrough,tb_vaddr%s\n", scallopstate.g_log_disas ? ",disas" : "");
    fflush(scallopstate.g_out);

    Dl_info soinfo{};
     if (dladdr((void *)&qemu_plugin_install, &soinfo) && soinfo.dli_fname) {
         fprintf(stderr, "[branchlog] using plugin %s\n", soinfo.dli_fname);
         fflush(stderr);
     }
     
    scallopstate.getGates().initAll();
    //scallopstate.getGates().resumeAll();

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
