#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "autoshield.h"

#include <setjmp.h>
#include <signal.h>
#include <string.h>

static sigjmp_buf read_jmp;
static volatile sig_atomic_t read_active;
static struct sigaction old_segv;
static struct sigaction old_bus;

static void fault_handler(int signum)
{
    if (read_active) {
        siglongjmp(read_jmp, signum);
    }

    if (signum == SIGSEGV && old_segv.sa_handler) {
        old_segv.sa_handler(signum);
    }
#ifdef SIGBUS
    if (signum == SIGBUS && old_bus.sa_handler) {
        old_bus.sa_handler(signum);
    }
#endif
}

int safe_read(void *dst, const void *src, size_t len)
{
    struct sigaction action;
    int rc = 0;

    if (!dst || !src) {
        return -1;
    }

    memset(&action, 0, sizeof(action));
    action.sa_handler = fault_handler;
    sigemptyset(&action.sa_mask);

    sigaction(SIGSEGV, &action, &old_segv);
#ifdef SIGBUS
    sigaction(SIGBUS, &action, &old_bus);
#endif

    read_active = 1;
    if (sigsetjmp(read_jmp, 1) == 0) {
        memcpy(dst, src, len);
    } else {
        rc = -1;
    }
    read_active = 0;

    sigaction(SIGSEGV, &old_segv, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS, &old_bus, NULL);
#endif
    return rc;
}
