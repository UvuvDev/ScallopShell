#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include "scallop.h"


static const char *kSock = "/tmp/scallopshell.sock";

char g_sock_path[256] = {0};
static int g_ctrl_sock = -1;
static pthread_t g_ctrl_thread;

// CSTDLib is annoying
int isxdigit(int c)
{
  return (
          ((c >= '0') && (c <= '9')) || 
          ((c >= 'a') && (c <= 'f')) ||
          ((c >= 'A') && (c <= 'F'))
         );
}

static int replyf(int fd, const char *fmt, ...) {
  char buf[512];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
#ifdef MSG_NOSIGNAL
  return send(fd, buf, n, MSG_NOSIGNAL);
#else
  return write(fd, buf, n);
#endif
}


// replace your accept_cloexec with this:
static int accept_cloexec(int fd)
{
    int c;

#if defined(__linux__) && defined(SOCK_CLOEXEC)
    errno = 0;
    c = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (c >= 0)
        return c;
    if (errno != ENOSYS)
        return c; // accept4 exists; if it failed for another reason, return it
#endif

    // Fallback: accept then set CLOEXEC
    c = accept(fd, NULL, NULL);
    if (c >= 0)
    {
        int flags = fcntl(c, F_GETFD);
        if (flags != -1)
            (void)fcntl(c, F_SETFD, flags | FD_CLOEXEC);
    }
    return c;
}

static void reply_and_close(int cfd, const char *msg)
{
    size_t n = strlen(msg);
    ssize_t rc = send(cfd, msg, n, MSG_NOSIGNAL); // <- no SIGPIPE
    if (rc < 0)
    {
        int e = errno;
        fprintf(stderr, "[ctrl] send failed: %s\n", strerror(e));
    }
    close(cfd);
}

static int make_unix_listener(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    struct sockaddr_un addr = {0};
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    unlink(path);
    mode_t old = umask(0077);
    int rc = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old);
    if (rc < 0)
    {
        close(fd);
        return -1;
    }
    if (listen(fd, 4) < 0)
    {
        close(fd);
        unlink(path);
        return -1;
    }
    return fd;
}

// Read until '\n' or EOF, ignore EINTR, time out (2s) if nothing arrives.
static ssize_t read_line_with_timeout(int fd, char *out, size_t cap, int timeout_ms) {
  size_t used = 0;
  struct pollfd pfd = { .fd = fd, .events = POLLIN };

  for (;;) {
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr == 0) { errno = EAGAIN; return -1; }               // timeout
    if (pr < 0) {
      if (errno == EINTR) continue;
      return -1;
    }

    ssize_t r = read(fd, out + used, cap ? (ssize_t)(cap - used - 1) : 0);
    if (r < 0) {
      if (errno == EINTR) continue;     // retry
      return -1;                        // real error
    }
    if (r == 0) {                        // EOF
      if (used == 0) return 0;
      out[used] = 0;
      return (ssize_t)used;
    }

    // got bytes
    for (ssize_t i = 0; i < r; i++) {
      if (out[used] == '\n') {
        out[used] = 0;
        return (ssize_t)used;
      }
      used++;
      if (used + 1 >= cap) { out[used] = 0; return (ssize_t)used; }
    }
  }
}


static void *ctrl_loop(void *arg)
{
    (void)arg;
    for (;;)
    {

        dbg("Head of Control loop\n");
        int cfd = accept_cloexec(g_ctrl_sock);
        if (cfd < 0)
        {
            if (errno == EINTR)
                continue;
            perror("[ctrl] accept");
            dbg("fail to enter\n");
            break;
        }
        dbg("It entered the g_ctrl_sock\n");

        char buf[256];
        ssize_t n = read_line_with_timeout(cfd, buf, sizeof(buf), 2000);
        if (n <= 0) {            // timeout, EOF, or error
            if (n == 0) dbg("[ctrl] EOF before data\n");
            else if (errno == EAGAIN) dbg("[ctrl] timeout waiting for line\n");
            else dbg("[ctrl] read error: %d\n", errno);
            close(cfd);
            continue;
        }

        dbg("starting truncation\n");
        buf[n] = 0;
        // trim trailing whitespace
        for (ssize_t i = n - 1; i >= 0 && (buf[i] == '\n' || buf[i] == '\r' || buf[i] == ' ' || buf[i] == '\t'); --i)
            buf[i] = 0;


        dbg("[ctrl] accept fd=%d cmd='%s'\n", cfd, buf);
        if (!strncmp(buf, "ping", 4))
        {
            dbg("pong\n", cfd, buf);
            dprintf(cfd, "pong\n");
            
        }
        else if (!strncmp(buf, "status", 6))
        {
            uintptr_t lo = atomic_load(&g_filter_lo);
            uintptr_t hi = atomic_load(&g_filter_hi);
            dprintf(cfd, "status range=[0x%lx,0x%lx]\n",
                    (unsigned long)lo, (unsigned long)hi);
        }
        else if (!strncmp(buf, "pause", 5))
        {
            gate_pause_all();
            dprintf(cfd, "ok paused\n");
        }
        else if (!strncmp(buf, "resume", 6))
        {
            gate_resume_all();
            dprintf(cfd, "ok resumed\n");
        }
        else if (!strncmp(buf, "step", 4))
        {
            long nsteps = 1;
            (void)sscanf(buf + 4, "%ld", &nsteps);
            if (nsteps < 1)
                nsteps = 1;
            gate_pause_all();
            gate_give(0, nsteps);
            dprintf(cfd, "ok step %ld\n", nsteps);

            /* set address filter: "set afilter LO HI" (hex or dec) */
        }
        else if (!strncmp(buf, "set afilter ", 12))
        {
            unsigned long lo = 0, hi = (unsigned long)-1;
            if (sscanf(buf + 12, "%lx %lx", &lo, &hi) == 2)
            {
                atomic_store(&g_filter_lo, (uintptr_t)lo);
                atomic_store(&g_filter_hi, (uintptr_t)hi);
                dprintf(cfd, "ok afilter 0x%lx 0x%lx\n", lo, hi);
            }
            else
            {
                dprintf(cfd, "err bad_args\n");
            }

            /* get/set memory: "get memory LO;HI" or "set memory LO;HI" */
        }
        else if (!strncmp(buf, "get memory ", 11) || !strncmp(buf, "set memory ", 11))
        {
            int is_set = (buf[0] == 's');
            char *arg = buf + 11;
            char *semi = strchr(arg, ';');
            if (!semi)
            {
                dprintf(cfd, "err bad_args\n");
                close(cfd);
                g_req.hi = 0;
                g_req.lo = 0;
                continue;
            }
            *semi = 0;
            errno = 0;
            uint64_t lo = strtoull(arg, NULL, 0);
            uint64_t hi = strtoull(semi + 1, NULL, 0);
            if (errno || hi < lo)
            {
                dprintf(cfd, "err bad_range\n");
                close(cfd);
                g_req.hi = 0;
                g_req.lo = 0;
                continue;
            }

            bool paused = atomic_load_explicit(&g_gate[0].running, memory_order_relaxed) == 0;
            pthread_mutex_lock(&g_req_mu);
            g_req.kind = is_set ? REQ_SET_MEM : REQ_GET_MEM;
            g_req.lo = lo;
            g_req.hi = hi;
            g_req.done = false;
            g_req.ok = false;
            g_req.recredit = paused;
            pthread_mutex_unlock(&g_req_mu);

            /* nudge vCPU so service_pending_request runs */
            gate_give(0, 1);

            /* wait until plugin work is done */
            pthread_mutex_lock(&g_req_mu);
            while (!g_req.done)
                pthread_cond_wait(&g_req_cv, &g_req_mu);
            bool ok = g_req.ok;
            pthread_mutex_unlock(&g_req_mu);

            dprintf(cfd, "%s %s -> %s\n",
                    ok ? "ok" : "err",
                    is_set ? "memset" : "memdump",
                    *g_mem_path ? g_mem_path : "/tmp/branchmem.txt");

            /* get/set registers */
        }
        else if (!strncmp(buf, "get registers", 13) || !strncmp(buf, "set registers", 13))
        {
            int is_set = (buf[0] == 's');

            bool paused = atomic_load_explicit(&g_gate[0].running, memory_order_relaxed) == 0;
            pthread_mutex_lock(&g_req_mu);
            g_req.kind = is_set ? REQ_SET_REGS : REQ_GET_REGS;
            g_req.lo = 0;
            g_req.hi = 0;
            g_req.done = false;
            g_req.ok = false;
            g_req.recredit = paused;
            pthread_mutex_unlock(&g_req_mu);

            gate_give(0, 1);

            pthread_mutex_lock(&g_req_mu);
            while (!g_req.done)
                pthread_cond_wait(&g_req_cv, &g_req_mu);
            bool ok = g_req.ok;
            pthread_mutex_unlock(&g_req_mu);

            dprintf(cfd, "%s %s -> %s\n",
                    ok ? "ok" : "err",
                    is_set ? "regs set from" : "regs",
                    *g_reg_path ? g_reg_path : "/tmp/branchregs.txt");

            /* bare "LO;HI" shorthand to set range */
        }
        else
        {
            char *semi = strchr(buf, ';');
            if (semi && isxdigit((unsigned char)buf[0]))
            {
                *semi = 0;
                errno = 0;
                unsigned long lo = strtoull(buf, NULL, 0);
                unsigned long hi = strtoull(semi + 1, NULL, 0);
                if (!errno)
                {
                    atomic_store(&g_filter_lo, (uintptr_t)lo);
                    atomic_store(&g_filter_hi, (uintptr_t)hi);
                    dprintf(cfd, "ok range 0x%lx 0x%lx\n", lo, hi);
                }
                else
                {
                    dprintf(cfd, "err bad_range\n");
                }
            }
            else
            {
                dprintf(cfd, "err unknown_cmd\n");
            }
        }
        close(cfd);
    }
    return NULL;
}

int control_start(void)
{
    snprintf(g_sock_path, sizeof(g_sock_path), "%s", kSock);
    unlink(g_sock_path);
    g_ctrl_sock = make_unix_listener(g_sock_path);
    if (g_ctrl_sock < 0)
        return -1;
    pthread_create(&g_ctrl_thread, NULL, ctrl_loop, NULL);
    fprintf(stderr, "[branchlog] control socket: %s\n", g_sock_path);
    return 0;
}

void control_stop(void)
{
    if (g_ctrl_sock >= 0)
    {
        close(g_ctrl_sock);
        unlink(g_sock_path);
        g_ctrl_sock = -1;
    }
}
