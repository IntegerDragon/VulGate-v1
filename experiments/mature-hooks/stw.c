/* Signal-based stop-the-world helper for the mature-hook experiment.
 *
 * All threads except the caller (and Frida's own helper threads) are asked to
 * enter a signal handler and spin there. The caller then patches code, sets the
 * release flag, and waits until every parked thread leaves the handler. */
#define _GNU_SOURCE
#include <dirent.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#define STW_SIGNAL (SIGRTMIN + 4)
#define STW_MAX_THREADS 512
#define STW_TIMEOUT_MS 500

static _Atomic unsigned stw_epoch;
static _Atomic unsigned stw_release_epoch;
static _Atomic int stw_active;
static _Atomic int stw_count;
static pid_t stw_tids[STW_MAX_THREADS];
static uintptr_t stw_pcs[STW_MAX_THREADS];
static _Atomic unsigned parked_epoch[STW_MAX_THREADS];
static uintptr_t parked_pc[STW_MAX_THREADS];
static pid_t known_tids[STW_MAX_THREADS];
static int known_count;

static unsigned long long stw_rounds;
static unsigned long long stw_retries;
unsigned long long stw_last_dirty;
unsigned long long stw_last_expected;
unsigned long long stw_last_active;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int snapshot_threads(void)
{
    DIR *dir = opendir("/proc/self/task");
    if (!dir) {
        return 0;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        if (count < STW_MAX_THREADS) {
            known_tids[count++] = (pid_t)atoi(entry->d_name);
        }
    }
    closedir(dir);
    known_count = count;
    return count;
}

/* Threads of the target program, supplied by the injector before the agent is
 * loaded (Frida's helper threads are not part of this set). */
void stw_set_known_threads(const pid_t *tids, int count)
{
    if (count < 0) {
        count = 0;
    }
    if (count > STW_MAX_THREADS) {
        count = STW_MAX_THREADS;
    }
    for (int index = 0; index < count; index++) {
        known_tids[index] = tids[index];
    }
    known_count = count;
}

static int is_known_thread(pid_t tid)
{
    for (int index = 0; index < known_count; index++) {
        if (known_tids[index] == tid) {
            return 1;
        }
    }
    return 0;
}

static int list_threads(pid_t *tids, int max, pid_t self)
{
    DIR *dir = opendir("/proc/self/task");
    if (!dir) {
        return 0;
    }
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        pid_t tid = (pid_t)atoi(entry->d_name);
        if (tid == self || !is_known_thread(tid)) {
            continue;
        }
        if (count < max) {
            tids[count++] = tid;
        }
    }
    closedir(dir);
    return count;
}

static void park_handler(int signal, siginfo_t *info, void *context)
{
    (void)signal;
    (void)info;
    unsigned epoch = atomic_load(&stw_epoch);
    pid_t tid = (pid_t)syscall(SYS_gettid);
    ucontext_t *ucontext = (ucontext_t *)context;
    atomic_fetch_add(&stw_count, 1);
    for (int index = 0; index < known_count; index++) {
        if (known_tids[index] == tid) {
            parked_pc[index] = (uintptr_t)ucontext->uc_mcontext.gregs[REG_RIP];
            atomic_store(&parked_epoch[index], epoch);
            break;
        }
    }
    atomic_fetch_add(&stw_active, 1);
    while (atomic_load(&stw_release_epoch) < epoch) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#else
        __asm__ __volatile__("");
#endif
    }
    atomic_fetch_sub(&stw_active, 1);
}

__attribute__((constructor))
static void stw_init(void)
{
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = park_handler;
    action.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&action.sa_mask);
    sigaction(STW_SIGNAL, &action, NULL);
    snapshot_threads();
}

/* Park every non-Frida thread except the caller. Returns 0 on success, -1 when
 * not every thread could be parked within the timeout. */
static int stw_begin(uintptr_t range_start, size_t range_size,
                     uintptr_t range2_start, size_t range2_size,
                     unsigned long long *dirty_threads)
{
    pid_t self = (pid_t)syscall(SYS_gettid);
    pid_t tids[STW_MAX_THREADS];
    uint64_t wait_deadline = now_ms() + 500;
    while (atomic_load(&stw_active) > 0 && now_ms() < wait_deadline) {
        __asm__ __volatile__("pause");
    }
    unsigned epoch = atomic_fetch_add(&stw_epoch, 1) + 1;
    int count = list_threads(tids, STW_MAX_THREADS, self);
    atomic_store(&stw_active, 0);
    atomic_store(&stw_count, 0);
    if (dirty_threads) {
        *dirty_threads = 0;
    }
    stw_rounds++;
    for (int index = 0; index < count; index++) {
        syscall(SYS_tgkill, getpid(), tids[index], STW_SIGNAL);
    }
    uint64_t deadline = now_ms() + STW_TIMEOUT_MS;
    for (;;) {
        int parked = 0;
        for (int index = 0; index < count; index++) {
            if (atomic_load(&parked_epoch[index]) == epoch) {
                parked++;
            }
        }
        if (parked == count || now_ms() >= deadline) {
            stw_last_expected = (unsigned long long)count;
            stw_last_active = (unsigned long long)parked;
            if (parked < count) {
                atomic_store(&stw_release_epoch, epoch);
                return -1;
            }
            break;
        }
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#endif
    }
    stw_last_dirty = 0;
    if (dirty_threads) {
        for (int index = 0; index < count; index++) {
            uintptr_t pc = parked_pc[index];
            if ((pc >= range_start && pc < range_start + range_size) ||
                (pc >= range2_start && pc < range2_start + range2_size)) {
                (*dirty_threads)++;
            }
        }
        stw_last_dirty = *dirty_threads;
    }
    return 0;
}

static void stw_end(void)
{
    unsigned epoch = atomic_load(&stw_epoch);
    atomic_store(&stw_release_epoch, epoch);
    uint64_t deadline = now_ms() + 500;
    while (atomic_load(&stw_active) > 0 && now_ms() < deadline) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#endif
    }
}

/* Park threads until none of them has a PC inside the patch range. */
/* Called before the injector unloads this library. Pending real-time signals
 * must not be delivered into unmapped code after dlclose. */
void stw_cleanup(void)
{
    uint64_t deadline = now_ms() + 1000;
    while (atomic_load(&stw_active) > 0 && now_ms() < deadline) {
#if defined(__x86_64__)
        __asm__ __volatile__("pause");
#endif
    }
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_IGN;
    sigemptyset(&action.sa_mask);
    sigaction(STW_SIGNAL, &action, NULL);
}

static int stw_begin_clean(uintptr_t range_start, size_t range_size,
                           uintptr_t range2_start, size_t range2_size,
                           int max_attempts)
{
    for (int attempt = 0; attempt < max_attempts; attempt++) {
        unsigned long long dirty = 0;
        if (stw_begin(range_start, range_size, range2_start, range2_size, &dirty) != 0) {
            stw_retries++;
            stw_end();
            usleep(200);
            continue;
        }
        if (dirty == 0) {
            return 0;
        }
        stw_retries++;
        stw_end();
        usleep(200);
    }
    return -2;
}




