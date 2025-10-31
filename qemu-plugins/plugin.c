#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "scallop.h"

/* Export version symbol */
QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* output file paths */
char g_mem_path[256] = {0};
char g_reg_path[256] = {0};

static void plugin_exit(qemu_plugin_id_t id, void *u){
  (void)id; (void)u;
  control_stop();
  if (g_out && g_out != stderr){ fflush(g_out); fclose(g_out); g_out=NULL; }
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info, int argc, char **argv){
  (void)info;
  const char *outfile = NULL;

  for (int i=0;i<argc;i++){
    if (!strncmp(argv[i],"file=",5))        outfile = argv[i]+5;
    else if (!strncmp(argv[i],"out=",4))    outfile = argv[i]+4;
    else if (!strcmp(argv[i],"disas=1"))    g_log_disas = 1;
    else if (!strncmp(argv[i],"memfile=",8)) snprintf(g_mem_path,sizeof(g_mem_path),"%s",argv[i]+8);
    else if (!strncmp(argv[i],"regfile=",8)) snprintf(g_reg_path,sizeof(g_reg_path),"%s",argv[i]+8);
  }
  if (!*g_mem_path) snprintf(g_mem_path,sizeof(g_mem_path),"/tmp/branchmem.%ld.txt",(long)getpid());
  if (!*g_reg_path) snprintf(g_reg_path,sizeof(g_reg_path),"/tmp/branchregs.%ld.txt",(long)getpid());

  g_out = outfile ? fopen(outfile,"w") : stderr;
  if (!g_out){ fprintf(stderr,"[branchlog] failed to open '%s'\n", outfile); g_out = stderr; }
  setvbuf(g_out, NULL, _IOLBF, 0);

  fprintf(g_out,"pc,kind,branch_target,fallthrough,tb_vaddr%s\n", g_log_disas?",disas":"");
  fflush(g_out);
  
  gate_init_all();
  if (control_start() < 0){
    fprintf(stderr,"[branchlog] WARNING: control socket failed\n");
  }

  qemu_plugin_register_vcpu_init_cb(id, vcpu_init_cb);
  qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans_cb);
  qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
  return 0;
}
