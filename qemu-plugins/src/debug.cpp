#include "debug.hpp"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>

int g_dbg_fd = -1;

void initDebug(void) {
    if (g_dbg_fd >= 0) return;
    signal(SIGPIPE, SIG_IGN);                        // never die on EPIPE
    g_dbg_fd = open("/tmp/branchlog.plugin.log",
                    O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0644);
}

void debug(const char *fmt, ...) {
  static int fd = -1;
  if (fd < 0) {
    signal(SIGPIPE, SIG_IGN);
    fd = open("/tmp/branchlog.plugin.log", O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC, 0644);
  }
  if (fd < 0) return;
  char buf[1024];
  va_list ap; va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n > 0) write(fd, buf, (n > (int)sizeof(buf) ? (int)sizeof(buf) : n));
}