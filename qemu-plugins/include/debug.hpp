#pragma once
#include "main.hpp"

extern int g_dbg_fd;

void initDebug(void);

void debug(const char *fmt, ...);