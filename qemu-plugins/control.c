#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "scallop.h"

static const char* kScallopSockPath = "/tmp/scallopshell.sock";

static inline int hexval(int c){
  if (c>='0'&&c<='9') return c-'0';
  if (c>='a'&&c<='f') return 10+(c-'a');
  if (c>='A'&&c<='F') return 10+(c-'A');
  return -1;
}

// This thing wants to be annoying so i have to redefine stdlib C. Sorry future me.
int isxdigit(int c)
{
  return (
          ((c >= '0') && (c <= '9')) || 
          ((c >= 'a') && (c <= 'f')) ||
          ((c >= 'A') && (c <= 'F'))
         );
}

// replace your accept_cloexec with this:
static int accept_cloexec(int fd) {
    int c;

#if defined(__linux__) && defined(SOCK_CLOEXEC)
    errno = 0;
    c = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (c >= 0) return c;
    if (errno != ENOSYS) return c;  // accept4 exists; if it failed for another reason, return it
#endif

    // Fallback: accept then set CLOEXEC
    c = accept(fd, NULL, NULL);
    if (c >= 0) {
        int flags = fcntl(c, F_GETFD);
        if (flags != -1) (void)fcntl(c, F_SETFD, flags | FD_CLOEXEC);
    }
    return c;
}


char g_sock_path[256] = {0};
static int      g_ctrl_sock = -1;
static pthread_t g_ctrl_thread;

static int make_unix_listener(const char *path){
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd<0) return -1;
  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
  unlink(path);
  mode_t old = umask(0077);
  int rc = bind(fd, (struct sockaddr*)&addr, sizeof(addr));
  umask(old);
  if (rc<0){ close(fd); return -1; }
  if (listen(fd, 4)<0){ close(fd); unlink(path); return -1; }
  return fd;
}

static void *ctrl_loop(void *arg){
  (void)arg;
  for(;;){
    int cfd = accept_cloexec(g_ctrl_sock);
    if (cfd<0){ if (errno==EINTR) continue; break; }
    char buf[256];
    ssize_t n = read(cfd, buf, sizeof(buf)-1);
    if (n<=0){ close(cfd); continue; }
    buf[n]=0;
    /* trim */
    for (ssize_t i=n-1;i>=0 && (buf[i]=='\n'||buf[i]=='\r'||buf[i]==' '||buf[i]=='\t');--i) buf[i]=0;

    if (!strncmp(buf,"pause",5)) {
        gate_pause_all(); dprintf(cfd,"ok paused\n");

    } else if (!strncmp(buf,"resume",6)) {
        gate_resume_all(); dprintf(cfd,"ok resumed\n");

    } else if (!strncmp(buf,"step",4)) {
        long nsteps=1; (void)sscanf(buf+4,"%ld",&nsteps); if (nsteps<1) nsteps=1;
        gate_pause_all(); gate_give(0,nsteps); dprintf(cfd,"ok step %ld\n", nsteps);

    } else if (!strncmp(buf,"set afilter ",12)) {
        uint64_t lo=0,hi=(uint64_t)-1;
        if (sscanf(buf+12,"%lx %lx",&lo,&hi)==2) {
            atomic_store(&g_filter_lo,(uintptr_t)lo);
            atomic_store(&g_filter_hi,(uintptr_t)hi);
            dprintf(cfd,"ok afilter 0x%lx 0x%lx\n", lo, hi);
        } else dprintf(cfd,"err bad_args\n");

    /* ---- get/set memory ---- */
    } else if (!strncmp(buf,"get memory ",11) || !strncmp(buf,"set memory ",11)) {
        int is_set = (buf[0]=='s');                 // 's'et vs 'g'et
        char *arg = buf + 11;
        char *semi2 = strchr(arg,';');
        if (!semi2){ dprintf(cfd,"err bad_args\n"); close(cfd); continue; }
        *semi2 = 0;

        errno = 0;
        uint64_t lo = strtoull(arg, NULL, 0);
        uint64_t hi = strtoull(semi2+1, NULL, 0);
        if (errno || hi < lo){ dprintf(cfd,"err bad_range\n"); close(cfd); continue; }

        /* enqueue */
        pthread_mutex_lock(&g_req_mu);
        g_req.kind = is_set ? REQ_SET_MEM : REQ_GET_MEM;
        g_req.lo   = lo;
        g_req.hi   = hi;
        g_req.done = false;
        g_req.ok   = false;
        pthread_mutex_unlock(&g_req_mu);

        /* nudge vCPU so service_pending_request runs */
        gate_give(0, 1);

        /* wait */
        pthread_mutex_lock(&g_req_mu);
        while (!g_req.done) pthread_cond_wait(&g_req_cv, &g_req_mu);
        bool ok = g_req.ok;
        pthread_mutex_unlock(&g_req_mu);

        dprintf(cfd, "%s %s -> %s\n",
                ok ? "ok" : "err",
                is_set ? "memset" : "memdump",
                *g_mem_path ? g_mem_path : "/tmp/branchmem.txt");

    /* ---- get/set memory ---- */
    } else if (!strncmp(buf,"get memory ",11) || !strncmp(buf,"set memory ",11)) {
        int is_set = (buf[0]=='s');                 // 's'et vs 'g'et
        char *arg = buf + 11;
        char *semi2 = strchr(arg,';');
        if (!semi2){ dprintf(cfd,"err bad_args\n"); close(cfd); continue; }
        *semi2 = 0;

        errno = 0;
        uint64_t lo = strtoull(arg, NULL, 0);
        uint64_t hi = strtoull(semi2+1, NULL, 0);
        if (errno || hi < lo){ dprintf(cfd,"err bad_range\n"); close(cfd); continue; }

        /* enqueue */
        pthread_mutex_lock(&g_req_mu);
        g_req.kind = is_set ? REQ_SET_MEM : REQ_GET_MEM;
        g_req.lo   = lo;
        g_req.hi   = hi;
        g_req.done = false;
        g_req.ok   = false;
        pthread_mutex_unlock(&g_req_mu);

        /* nudge vCPU so service_pending_request runs */
        gate_give(0, 1);

        /* wait */
        pthread_mutex_lock(&g_req_mu);
        while (!g_req.done) pthread_cond_wait(&g_req_cv, &g_req_mu);
        bool ok = g_req.ok;
        pthread_mutex_unlock(&g_req_mu);

        dprintf(cfd, "%s %s -> %s\n",
                ok ? "ok" : "err",
                is_set ? "memset" : "memdump",
                *g_mem_path ? g_mem_path : "/tmp/branchmem.txt");

    /* ---- get/set registers ---- */
    } else if (!strncmp(buf,"get registers",13) || !strncmp(buf,"set registers",13)) {
        int is_set = (buf[0]=='s');

        /* enqueue */
        pthread_mutex_lock(&g_req_mu);
        g_req.kind = is_set ? REQ_SET_REGS : REQ_GET_REGS;
        g_req.lo   = 0;
        g_req.hi   = 0;
        g_req.done = false;
        g_req.ok   = false;
        pthread_mutex_unlock(&g_req_mu);

        /* nudge vCPU */
        gate_give(0, 1);

        /* wait */
        pthread_mutex_lock(&g_req_mu);
        while (!g_req.done) pthread_cond_wait(&g_req_cv, &g_req_mu);
        bool ok = g_req.ok;
        pthread_mutex_unlock(&g_req_mu);

        dprintf(cfd, "%s %s -> %s\n",
                ok ? "ok" : "err",
                is_set ? "regs set from" : "regs",
                *g_reg_path ? g_reg_path : "/tmp/branchregs.txt");

    /* ---- ONLY NOW handle the bare "LOW;HIGH" shorthand ---- */
    } else {
        char *semi = strchr(buf,';');
        if (semi && isxdigit((unsigned char)buf[0])) {
            *semi = 0;
            char *lhs = buf, *rhs = semi+1;
            while (*lhs==' '||*lhs=='\t') lhs++;
            while (*rhs==' '||*rhs=='\t') rhs++;
            errno = 0;
            unsigned long long lo = strtoull(lhs,NULL,0);
            unsigned long long hi = strtoull(rhs,NULL,0);
            if (!errno){
                atomic_store(&g_filter_lo, (uintptr_t)lo);
                atomic_store(&g_filter_hi, (uintptr_t)hi);
                dprintf(cfd,"ok range 0x%llx 0x%llx\n", lo, hi);
            } else dprintf(cfd,"err bad_range\n");
        } else {
            dprintf(cfd,"err unknown_cmd\n");
        }
    }

    close(cfd);
  }
  return NULL;
}

int control_start(void){
  snprintf(g_sock_path, sizeof(g_sock_path), "%s", kScallopSockPath);

  // Ensure any stale socket from a previous crash is removed
  unlink(g_sock_path);
  g_ctrl_sock = make_unix_listener(g_sock_path);
  if (g_ctrl_sock < 0) return -1;
  pthread_create(&g_ctrl_thread,NULL,ctrl_loop,NULL);
  fprintf(stderr,"[branchlog] control socket: %s\n", g_sock_path);
  return 0;
}
void control_stop(void){
    if (g_ctrl_sock>=0){
        close(g_ctrl_sock);
        // Clean up the fixed socket path
        unlink(g_sock_path[0] ? g_sock_path : kScallopSockPath);
        g_ctrl_sock=-1;
    }
}
