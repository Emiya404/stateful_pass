/*
  Copyright 2015 Google LLC All rights reserved.

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
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This code is the rewrite of afl-as.h's main_payload.
*/
#define AFLNET_STATE_AWARE
#include "../android-ashmem.h"
#include "../config.h"
#include "../types.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>


/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;
/*
  SHM for fuzzer state trace
*/
u8  __fstate_area_initial[MAP_SIZE << 10];
u8* __fstate_shm_ptr = __fstate_area_initial;
u8* __fstate_shm_start = __fstate_area_initial;
u32 bucket_size;
u32 __fstate_bucket_count;
u32 __fstate_current_state;


u8* create_bucket(){

  if(!bucket_size){
    return NULL;
  }
  u8* new_bucket = __fstate_shm_start + ((bucket_size + 4) * __fstate_bucket_count);
  //new bucket
  if(*(u32*)new_bucket == 0xdeadbeef){
    
    return new_bucket;
  }
  
  return NULL;
}

#ifdef AFLNET_STATE_AWARE



int aflnet_openssl_extract(u8* buf, int len){

  char *mem;
  unsigned int byte_count = 0;
  unsigned int mem_count = 0;
  unsigned int mem_size = 1024;
  unsigned char content_type, message_type;
  unsigned int *state_sequence = NULL;
  unsigned int state_count = 0;
  mem=(char *)malloc(mem_size);
  while (byte_count < len) {

    memcpy(&mem[mem_count], buf + byte_count++, 1);

    //Check if the region buffer length is at least 6 bytes (5 bytes for record header size)
    //the 6th byte could be message type
    if (mem_count >= 6) {
      //1st byte: content type
      //2nd and 3rd byte: TLS version
      //Extract the message size stored in the 4th and 5th bytes
      content_type = mem[0];

      //Check if this is an application data record
      if (content_type != 0x17) {
        message_type = mem[5];
      } else {
        message_type = 0xFF;
      }

      u16* size_buf = (u16*)&mem[3];
      u16 message_size = (u16)ntohs(*size_buf);

      //and skip the payload
      unsigned int bytes_to_skip = message_size - 1;
      unsigned int temp_count = 0;
      while ((byte_count < len) && (temp_count < bytes_to_skip)) {
        byte_count++;
        temp_count++;
      }

      if (byte_count < len) {
          byte_count--;
      }

      //add a new response code
      unsigned int message_code = (content_type << 8) + message_type;
      state_count++;
      mem_count = 0;
      //write new bucket in the shm
      __fstate_bucket_count++;
      u8* new_bucket = create_bucket();
      if(!new_bucket){
        _exit(1);
      }
      *(u32*)new_bucket = message_code;
      __fstate_current_state = message_code;
      memset(new_bucket + 4, 0x0, bucket_size);
      *(u32*)(new_bucket + 4 + bucket_size) = 0xdeadbeef;

    } else {
      mem_count++;
      if (mem_count == mem_size) {
        //enlarge the mem buffer
        mem_size = mem_size * 2;
        mem=(char *)realloc(mem, mem_size);
      }
    }
  }
  if (mem) free(mem);

  return 0;
}

#endif



int fstate_extract(){
  return __fstate_current_state;
}

#ifdef NEED_TRACE_INFO

int fname_store(int code){
  if(__fstate_shm_ptr!=(void*)-1 && __fstate_shm_ptr){
    *(u32*)__fstate_shm_ptr = code;
    __fstate_shm_ptr += 4;
    return 0;
  }
  return -1;
}
#else

int fname_store(int func_idx, int bucket_idx){
  if(__fstate_shm_ptr!=(void*)-1 && __fstate_shm_ptr){
    *(__fstate_shm_start + (bucket_idx * (bucket_size + 4) + 4 + func_idx)) = 1;
  }
}

#endif

__thread u32 __afl_prev_loc;


/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }
  /*
    init call trace SHM ptr in forkserver
  */
  
  u8 *fstate_str = getenv("__FSTATE_SHM_ID");
  if(fstate_str){
    u32 fstate_id = atoi(fstate_str);
    __fstate_shm_start = __fstate_shm_ptr = shmat(fstate_id, NULL, 0);
    if(__fstate_shm_ptr == (void*)-1){
      _exit(1);
    }
  }
  
  
}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


int init_bucket(){

  int func_count_fd = open("/home/ubuntu/func_count.txt", O_RDONLY);
  if(func_count_fd < 0){
    _exit(1);
  }
  char buf[100];
  memset(buf, 0x0, 100);
  lseek(func_count_fd, 0, SEEK_SET);
  read(func_count_fd, buf, 100);
  bucket_size = atoi(buf);
  //align up 4 bytes
  bucket_size = (bucket_size + 3) & (~3);

  #ifndef NEED_TRACE_INFO
    memset(__fstate_shm_start, 0x0, bucket_size + 4);
    *(u32*)(__fstate_shm_start + bucket_size + 4) = 0xdeadbeef;
  #endif
  close(func_count_fd);

}

/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }
  init_bucket();

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}
