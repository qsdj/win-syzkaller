// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.
// csource does a bunch of transformations with this file:
// - unused parts are stripped using #if SYZ* defines
// - includes are hoisted to the top and deduplicated
// - comments and empty lines are stripped
// - NORETURN/PRINTF/debug are removed
// - exitf/failf/fail are replaced with exit
// - uintN types are replaced with uintN_t
// - [[FOO]] placeholders are replaced by actual values

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdio.h> // for fmt arguments
#include <stdlib.h>
#include <string.h>

#include "common_windows.h"
#if SYZ_TRACE
#include <errno.h>
#endif

NORETURN void doexit(int status)
{
	_exit(status);
	for (;;) {
	}
}

unsigned long long procid;

#if !GOOS_linux
#if (SYZ_EXECUTOR || SYZ_REPEAT) && SYZ_EXECUTOR_USES_FORK_SERVER
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

static void kill_and_wait(int pid, int* status)
{
	kill(pid, SIGKILL);
	while (waitpid(-1, status, 0) != pid) {
	}
}
#endif
#endif

#if !GOOS_linux
#if SYZ_EXECUTOR || SYZ_FAULT_INJECTION
static int inject_fault(int nth)
{
	return 0;
}
#endif
#if SYZ_EXECUTOR
static int fault_injected(int fail_fd)
{
	return 0;
}
#endif
#endif

#if SYZ_EXECUTOR || SYZ_USE_BITMASKS
#define BITMASK(bf_off, bf_len) (((1ull << (bf_len)) - 1) << (bf_off))
#define STORE_BY_BITMASK(type, htobe, addr, val, bf_off, bf_len)                        \
	*(type*)(addr) = htobe((htobe(*(type*)(addr)) & ~BITMASK((bf_off), (bf_len))) | \
			       (((type)(val) << (bf_off)) & BITMASK((bf_off), (bf_len))))
#endif

struct csum_inet {
	uint32_t acc;
};

void csum_inet_init(struct csum_inet* csum)
{
	csum->acc = 0;
}

static void csum_inet_update(struct csum_inet* csum, const uint8_t* data, size_t length)
{
	if (length == 0)
		return;

	size_t i;
	for (i = 0; i < length - 1; i += 2)
		csum->acc += *(uint16_t*)&data[i];

	if (length & 1)
		csum->acc += (uint16_t)data[length - 1];

	while (csum->acc > 0xffff)
		csum->acc = (csum->acc & 0xffff) + (csum->acc >> 16);
}

static uint16_t csum_inet_digest(struct csum_inet* csum)
{
	return ~csum->acc;
}


#if SYZ_EXECUTOR || __NR_syz_execute_func
// syz_execute_func(text ptr[in, text[taget]])
static long syz_execute_func(long text)
{
	((void (*)(void))(text))();
	return 0;
}
#endif



#if SYZ_THREADED
struct thread_t {
	int created, call;
	event_t ready, done;
};

static struct thread_t threads[16];
static void execute_call(thread_t* th);
static int running;

static void* thr(void* arg)
{
	struct thread_t* th = (struct thread_t*)arg;
	for (;;) {
		event_wait(&th->ready);
		event_reset(&th->ready);
		execute_call(th->call);
		__atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
		event_set(&th->done);
	}
	return 0;
}

#if SYZ_REPEAT
static void execute_one(void)
#else
static void loop(void)
#endif
{
#if SYZ_REPRO
	if (write(1, "executing program\n", sizeof("executing program\n") - 1)) {
	}
#endif
#if SYZ_TRACE
	printf("### start\n");
#endif
	int i, call, thread;
#if SYZ_COLLIDE
	int collide = 0;
again:
#endif
	for (call = 0; call < [[NUM_CALLS]]; call++) {
		for (thread = 0; thread < (int)(sizeof(threads) / sizeof(threads[0])); thread++) {
			struct thread_t* th = &threads[thread];
			if (!th->created) {
				th->created = 1;
				event_init(&th->ready);
				event_init(&th->done);
				event_set(&th->done);
				thread_start(thr, th);
			}
			if (!event_isset(&th->done))
				continue;
			event_reset(&th->done);
			th->call = call;
			__atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
			event_set(&th->ready);
#if SYZ_COLLIDE
			if (collide && (call % 2) == 0)
				break;
#endif
			event_timedwait(&th->done, 45);
			break;
		}
	}
	for (i = 0; i < 100 && __atomic_load_n(&running, __ATOMIC_RELAXED); i++)
		sleep_ms(1);
#if SYZ_COLLIDE
	if (!collide) {
		collide = 1;
		goto again;
	}
#endif
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
static void execute_one(void);
#if SYZ_EXECUTOR_USES_FORK_SERVER
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#define WAIT_FLAGS 0

#if SYZ_EXECUTOR
static void reply_handshake();
#endif

static void loop(void)
{
#if SYZ_HAVE_SETUP_LOOP
	setup_loop();
#endif
#if SYZ_EXECUTOR
	// Tell parent that we are ready to serve.
	reply_handshake();
#endif
#if SYZ_EXECUTOR && GOOS_akaros
	// For akaros we do exec in the child process because new threads can't be created in the fork child.
	// Thus we proxy input program over the child_pipe to the child process.
	int child_pipe[2];
	if (pipe(child_pipe))
		fail("pipe failed");
#endif
	int iter;
#if SYZ_REPEAT_TIMES
	for (iter = 0; iter < [[REPEAT_TIMES]]; iter++) {
#else
	for (iter = 0;; iter++) {
#endif
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
		// Create a new private work dir for this test (removed at the end of the loop).
		char cwdbuf[32];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");
#endif
#if SYZ_HAVE_RESET_LOOP
		reset_loop();
#endif
#if SYZ_EXECUTOR
		receive_execute();
#endif
		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
			if (chdir(cwdbuf))
				fail("failed to chdir");
#endif
#if SYZ_HAVE_SETUP_TEST
			setup_test();
#endif
#if GOOS_akaros
#if SYZ_EXECUTOR
			dup2(child_pipe[0], kInPipeFd);
			close(child_pipe[0]);
			close(child_pipe[1]);
#endif
			execl(program_name, program_name, "child", NULL);
			fail("execl failed");
#else
#if SYZ_EXECUTOR
			close(kInPipeFd);
#endif
#if SYZ_EXECUTOR && SYZ_EXECUTOR_USES_SHMEM
			close(kOutPipeFd);
#endif
			execute_one();
#if SYZ_HAVE_RESET_TEST
			reset_test();
#endif
			doexit(0);
#endif
		}
		debug("spawned worker pid %d\n", pid);

#if SYZ_EXECUTOR && GOOS_akaros
		resend_execute(child_pipe[1]);
#endif
		// We used to use sigtimedwait(SIGCHLD) to wait for the subprocess.
		// But SIGCHLD is also delivered when a process stops/continues,
		// so it would require a loop with status analysis and timeout recalculation.
		// SIGCHLD should also unblock the usleep below, so the spin loop
		// should be as efficient as sigtimedwait.
		int status = 0;
		uint64_t start = current_time_ms();
#if SYZ_EXECUTOR && SYZ_EXECUTOR_USES_SHMEM
		uint64_t last_executed = start;
		uint32_t executed_calls = __atomic_load_n(output_data, __ATOMIC_RELAXED);
#endif
		for (;;) {
			if (waitpid(-1, &status, WNOHANG | WAIT_FLAGS) == pid)
				break;
			sleep_ms(1);
#if SYZ_EXECUTOR && SYZ_EXECUTOR_USES_SHMEM
			// Even though the test process executes exit at the end
			// and execution time of each syscall is bounded by 20ms,
			// this backup watchdog is necessary and its performance is important.
			// The problem is that exit in the test processes can fail (sic).
			// One observed scenario is that the test processes prohibits
			// exit_group syscall using seccomp. Another observed scenario
			// is that the test processes setups a userfaultfd for itself,
			// then the main thread hangs when it wants to page in a page.
			// Below we check if the test process still executes syscalls
			// and kill it after 1s of inactivity.
			uint64_t now = current_time_ms();
			uint32_t now_executed = __atomic_load_n(output_data, __ATOMIC_RELAXED);
			if (executed_calls != now_executed) {
				executed_calls = now_executed;
				last_executed = now;
			}
			if ((now - start < 5 * 1000) && (now - start < 3 * 1000 || now - last_executed < 1000))
				continue;
#else
			if (current_time_ms() - start < 5 * 1000)
				continue;
#endif
			debug("killing hanging pid %d\n", pid);
			kill_and_wait(pid, &status);
			break;
		}
#if SYZ_EXECUTOR
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		reply_execute(0);
#endif
#if SYZ_EXECUTOR || SYZ_USE_TMP_DIR
		remove_dir(cwdbuf);
#endif
	}
}
#else
static void loop(void)
{
	execute_one();
}
#endif
#endif

// clang-format off
// clang-format badly mishandles this part, moreover different versions mishandle it differently.
#if !SYZ_EXECUTOR
[[SYSCALL_DEFINES]]

[[RESULTS]]

#if SYZ_THREADED || SYZ_REPEAT || SYZ_SANDBOX_NONE || SYZ_SANDBOX_SETUID || SYZ_SANDBOX_NAMESPACE || SYZ_SANDBOX_ANDROID_UNTRUSTED_APP
#if SYZ_THREADED
void execute_call(int call)
#elif SYZ_REPEAT
void execute_one(void)
#else
void loop(void)
#endif
{
	[[SYSCALLS]]
}
#endif

// This is the main function for csource.
#if GOOS_akaros && SYZ_REPEAT
#include <string.h>

int main(int argc, char** argv)
{
	[[MMAP_DATA]]

	program_name = argv[0];
	if (argc == 2 && strcmp(argv[1], "child") == 0)
		child();
#else
int main(void)
{
	[[MMAP_DATA]]
#endif
		// clang-format on

#if SYZ_HANDLE_SEGV
	install_segv_handler();
#endif
#if SYZ_PROCS
	for (procid = 0; procid < [[PROCS]]; procid++) {
		if (fork() == 0) {
#endif
#if SYZ_USE_TMP_DIR || SYZ_SANDBOX_ANDROID_UNTRUSTED_APP
			use_temporary_dir();
#endif
			[[SANDBOX_FUNC]]
#if SYZ_PROCS
		}
	}
	sleep(1000000);
#endif
	return 0;
}
#endif
