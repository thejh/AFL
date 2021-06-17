#include "config.h"
#include <unistd.h>
#include <sys/wait.h>

__attribute__((weak)) void __afl_forkserver_c(void) {
  u32 dummy = 0;
  if (write(FORKSRV_FD + 1, &dummy, sizeof(dummy)) != sizeof(dummy))
    goto resume;
  while (1) {
    s32 child_pid;
    s32 wait_res;

    if (read(FORKSRV_FD, &dummy, sizeof(dummy)) != sizeof(dummy))
      _exit(0);
    child_pid = fork();
    if (child_pid == -1)
      _exit(0);
    if (child_pid == 0)
      goto resume;
    if (write(FORKSRV_FD + 1, &child_pid, sizeof(child_pid)) != sizeof(child_pid))
      _exit(0);
    if (waitpid(child_pid, &wait_res, 0) != child_pid)
      _exit(0);
    if (write(FORKSRV_FD + 1, &wait_res, sizeof(wait_res)) != sizeof(wait_res))
      _exit(0);
  }

resume:
  close(FORKSRV_FD);
  close(FORKSRV_FD+1);
}
