/*
  Copyright 2013 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - instrumentation benchmark
   ----------------------------------------------

   This is a helper for evaluating the performance impact of changes to
   AFL's instrumentation; you can ignore this if you are not making
   performance-relevant changes to instrumentation.
   It launches multiple forkserver-instrumented binaries, all with the same
   arguments, lets them run on the same testcase over and over again, and
   prints timing information that can e.g. be fed into gnuplot.

*/

#define _GNU_SOURCE
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/shm.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/personality.h>

#define MAX_TARGETS 128
#define MAX_CHILD_ARGS 128

static char **targets;
static int num_targets;
static char *child_argv[1 + MAX_CHILD_ARGS + 1];
static int st_pipes[MAX_TARGETS];
static int ctl_pipes[MAX_TARGETS];
static pid_t forksrv_pids[MAX_TARGETS];
static int dev_null_fd;

static u32 read_int(int fd) {
  u32 result;
  int len = read(fd, &result, sizeof(result));
  if (len != 4) FATAL("read from pipe");
  return result;
}

// get current time in microseconds, with the same clock as dmesg
static u64 getnanos(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    FATAL("clock_gettime()");
  return ts.tv_sec * (u64)1000000000 + ts.tv_nsec;
}

int main(int argc, char **argv) {
  int delim_idx;
  int num_args;
  int num_rounds;
  int i, j;
  int targets_idx = 3;
  s32 shm_id;
  u8 *shm_buf;
  char *shm_str;
  int interleave;

  setlinebuf(stdout);

  if (argc < 5)
    FATAL("not enough arguments - usage: %s <number of rounds> <grouped|interleaved> <target executables>... -- [<arguments>...]", argv[0]);
  num_rounds = atoi(argv[1]);
  if (num_rounds < 1)
    FATAL("invalid number of rounds");

  if (strcmp(argv[2], "grouped") == 0)
    interleave = 0;
  else if (strcmp(argv[2], "interleaved") == 0)
    interleave = 1;
  else
    FATAL("invalid mode");

  dev_null_fd = open("/dev/null", O_RDWR|O_CLOEXEC);
  if (dev_null_fd == -1)
    PFATAL("open /dev/null");

  for (delim_idx = targets_idx; ; delim_idx++) {
    if (delim_idx == argc)
      FATAL("no '--' delimiter in command line");
    if (strcmp(argv[delim_idx], "--") == 0)
      break;
  }
  num_targets = delim_idx - targets_idx;
  if (num_targets < 1 || num_targets > MAX_TARGETS)
    FATAL("can't deal with %d targets", num_targets);
  targets = argv + targets_idx;
  num_args = argc - (delim_idx + 1);
  if (num_args > MAX_CHILD_ARGS)
    FATAL("too many arguments for child");

  for (i = 0; i < num_args; i++)
    child_argv[1 + i] = argv[delim_idx + 1 + i];
  child_argv[1 + num_args] = NULL;

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) PFATAL("shmget() failed");
  shm_buf = shmat(shm_id, NULL, 0);
  shmctl(shm_id, IPC_RMID, NULL); /* must be after shmat() */
  if (shm_buf == (void*)-1) FATAL("shmat() failed");
  shm_str = (char*)alloc_printf("%d", shm_id);
  setenv(SHM_ENV_VAR, shm_str, 1);

  for (i = 0; i < num_targets; i++) {
    /* launch forkserver */
    int st_pipe[2], ctl_pipe[2];

    fprintf(stderr, "launching '%s'\n", targets[i]);

    if (pipe2(st_pipe, O_CLOEXEC) || pipe2(ctl_pipe, O_CLOEXEC))
      PFATAL("pipe() failed");
    st_pipes[i] = st_pipe[0];
    ctl_pipes[i] = ctl_pipe[1];

    forksrv_pids[i] = fork();
    if (forksrv_pids[i] == -1)
      PFATAL("fork() failed");

    if (forksrv_pids[i] == 0) {
      if (prctl(PR_SET_PDEATHSIG, SIGKILL)) PFATAL("PDEATHSIG");
      if (getppid() == 1) exit(42);

      if (personality(ADDR_NO_RANDOMIZE)) PFATAL("disabling ASLR");

      child_argv[0] = targets[i];
      setenv("LD_BIND_NOW", "1", 0);
      if (dup2(ctl_pipe[0], FORKSRV_FD) == -1) PFATAL("dup2() failed");
      if (dup2(st_pipe[1], FORKSRV_FD + 1) == -1) PFATAL("dup2() failed");
      dup2(dev_null_fd, 0);
      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      execvp(child_argv[0], child_argv);
      exit(42);
    }

    close(ctl_pipe[0]);
    close(st_pipe[1]);

    /* wait for forkserver to report ready */
    read_int(st_pipe[0]);
  }
  fprintf(stderr, "all forkservers up\n");

  for (i = 0; i < num_rounds; i++) {
    u64 target_times[MAX_TARGETS];
    for (j = 0; j < num_targets; j++)
      target_times[j] = 0;
    const int cycles = 256;
    for (j = 0; j < num_targets * cycles; j++) {
      int target = interleave ? (j % num_targets) : (j / cycles);
      u64 t1 = getnanos();
      u32 zero = 0;
      if (write(ctl_pipes[target], &zero, sizeof(zero)) != sizeof(zero))
        FATAL("command to forkserver failed");
      /*u32 pid = */read_int(st_pipes[target]);
      u32 exit_status = read_int(st_pipes[target]);
      if (!WIFEXITED(exit_status))
        FATAL("fuzzee did not exit cleanly");
      u64 t2 = getnanos();
      target_times[target] += t2 - t1;
    }
    printf("%d", i);
    for (j = 0; j < num_targets; j++)
      printf(" %llu", (unsigned long long)target_times[j]);
    printf("\n");
  }

  fprintf(stderr, "done\n");
  return 0;
}
