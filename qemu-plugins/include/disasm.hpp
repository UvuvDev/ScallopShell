#pragma once
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include "main.hpp"



static void log(unsigned int vcpu_index, void *udata);
void tb_trans_cb(qemu_plugin_id_t id, struct qemu_plugin_tb *tb);