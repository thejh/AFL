#define _GNU_SOURCE
#include "config.h"
#include <unistd.h>
#include <ucontext.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ucontext.h>

#if 0
/* do a syscall without touching errno */
static inline long do_syscall(unsigned long syscall_nr, unsigned long arg1, unsigned long arg2, unsigned long arg3) {
  unsigned long rax = syscall_nr;
  asm volatile(
    "syscall"
  : "+a"(rax)
  : "D"(arg1), "S"(arg2), "d"(arg3)
  : "cc", "memory", "c", 
  );
  return rax;
}
#endif

#define MAX_MAPPINGS 512
struct saved_mapping {
  char *start;
  unsigned long len;
  char *backup_data;
};
struct server_data {
  unsigned char guard1[0x1000] __attribute__((aligned(0x1000)));
  unsigned char stack[0x10000] __attribute__((aligned(0x1000)));
  ucontext_t orig_ctx;
  ucontext_t server_ctx;
  int forkserver_active;
  struct saved_mapping saved_mappings[MAX_MAPPINGS];
  int saved_mappings_count;
  unsigned char guard2[0x1000] __attribute__((aligned(0x1000)));
};
static struct server_data *sdata;

__attribute__((noreturn))
static void forkserver_core(void) {
  u32 dummy = 0;
  void *orig_brk = sbrk(0);

  /* parse maps to find RW mappings, and create read-only backups of them */
  {
    int maps_fd = open("/proc/self/maps", O_RDONLY);
    if (maps_fd == -1)
      _exit(123);
    char maps_line[0x1000];
    size_t maps_line_used = 0;
    size_t total_backup_len = 0;
    while (1) {
      char *line_end = memchr(maps_line, '\n', maps_line_used);
      if (line_end == NULL) {
        if (maps_line_used == sizeof(maps_line))
          _exit(123);
        int len = read(maps_fd, maps_line+maps_line_used, sizeof(maps_line)-maps_line_used);
        if (len == 0 && maps_line_used == 0)
          break;
        if (len <= 0)
          _exit(123);
        maps_line_used += len;
        continue;
      }
      size_t line_len = line_end - maps_line;

      char *post_end = memchr(maps_line, ' ', line_end-maps_line);
      if (!post_end) _exit(123);
      if (line_end - post_end < 5) _exit(123);
      if (post_end[2] != '-' && post_end[2] != 'w') _exit(123);
      if (post_end[2] == '-' || post_end[4] == 's')
        goto next_line;

      char *post_start;
      unsigned long start_addr = strtoul(maps_line, &post_start, 16);
      if (post_start[0] != '-')
        _exit(123);
      unsigned long end_addr = strtoul(post_start+1, NULL, 16);

      if (memmem(maps_line, line_len, "[stack]", 6))
        start_addr = sdata->orig_ctx.uc_mcontext.gregs[REG_RSP] - 128;

      /* ignore server_data */
      if (start_addr == (unsigned long)sdata->stack)
        goto next_line;

      if (sdata->saved_mappings_count == MAX_MAPPINGS)
        _exit(123);
      struct saved_mapping *sm = &sdata->saved_mappings[sdata->saved_mappings_count++];
      sm->start = (void*)start_addr;
      sm->len = end_addr - start_addr;
      total_backup_len += sm->len;
next_line:
      maps_line_used -= line_len+1;
      memmove(maps_line, line_end+1, maps_line_used);
    }
    close(maps_fd);

    char *backup_buf = mmap(NULL, total_backup_len, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (backup_buf == MAP_FAILED)
      _exit(123);
    size_t backup_off = 0;
    for (int i=0; i<sdata->saved_mappings_count; i++) {
      struct saved_mapping *sm = &sdata->saved_mappings[i];
      sm->backup_data = backup_buf + backup_off;
      memcpy(sm->backup_data, sm->start, sm->len);
      backup_off += sm->len;
    }
    if (mprotect(backup_buf, total_backup_len, PROT_READ))
      _exit(123);
  };

  if (write(FORKSRV_FD + 1, &dummy, sizeof(dummy)) != sizeof(dummy)) {
    sdata->forkserver_active = 0;
    setcontext(&sdata->orig_ctx);
    abort();
  }
  sdata->forkserver_active = 1;

  while (1) {
    s32 child_pid;
    s32 wait_res;

    if (read(FORKSRV_FD, &dummy, sizeof(dummy)) != sizeof(dummy))
      _exit(0);

#if 0
    child_pid = fork();
#endif
    child_pid = vfork();
    if (child_pid == -1)
      _exit(0);
    if (child_pid == 0) {
      /*
       * MUST NOT return here because the parent will continue to use the stack.
       * also can't write to variables or anything like that.
       */
      setcontext(&sdata->orig_ctx);
      abort();
    }

    /*
     * Note: We only continue running when the child is gone, and the child
     * takes care of telling the parent its PID.
     */
    if (waitpid(child_pid, &wait_res, 0) != child_pid)
      _exit(0);
    if (write(FORKSRV_FD + 1, &wait_res, sizeof(wait_res)) != sizeof(wait_res))
      _exit(0);

    /* roll back memory changes */
    if (brk(orig_brk))
      _exit(123);
    for (int i=0; i<sdata->saved_mappings_count; i++) {
      struct saved_mapping *sm = &sdata->saved_mappings[i];
      memcpy(sm->start, sm->backup_data, sm->len);
    }
  }
}

__attribute__((weak)) void __afl_forkserver_c(void) {
  int errno_ = errno;

  sdata = mmap(NULL, sizeof(struct server_data), PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  if (sdata == MAP_FAILED)
    _exit(123);
  if (mprotect(sdata->guard1, sizeof(sdata->guard1), PROT_NONE))
    _exit(123);
  if (mprotect(sdata->guard2, sizeof(sdata->guard2), PROT_NONE))
    _exit(123);

  /* call forkserver_core() on other stack */
  getcontext(&sdata->server_ctx);
  sdata->server_ctx.uc_stack.ss_sp = sdata->stack;
  sdata->server_ctx.uc_stack.ss_size = sizeof(sdata->stack);
  sdata->server_ctx.uc_link = (void*)0x123UL; /* poison value */
  makecontext(&sdata->server_ctx, forkserver_core, 0);
  swapcontext(&sdata->orig_ctx, &sdata->server_ctx);

  /* in vfork() child or forkserver-less execution: */
  if (sdata->forkserver_active) {
    pid_t child_pid = getpid();
    if (write(FORKSRV_FD + 1, &child_pid, sizeof(child_pid)) != sizeof(child_pid))
      _exit(0);
  }
  close(FORKSRV_FD);
  close(FORKSRV_FD+1);
  errno = errno_;
}
