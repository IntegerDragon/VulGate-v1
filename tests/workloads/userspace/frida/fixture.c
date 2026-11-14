/* Benign arithmetic fixture: the counter proves whether the body ran. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>

#ifdef _WIN32
#define ENTRY __declspec(dllexport) __attribute__((noinline))
#else
#define ENTRY __attribute__((visibility("default"), noinline))
#endif

static unsigned body_calls;
static volatile uint64_t observed_sink;
static int marked;

ENTRY void fixture_observe(uint64_t key, unsigned limit)
{
    observed_sink = key ^ limit;
}

ENTRY void fixture_clear(uint64_t key)
{
    observed_sink = key;
}

ENTRY int fixture_target(uint64_t key, unsigned value)
{
    (void)key;
    body_calls++;
    return 100 + (int)(value & 255);
}

ENTRY int fixture_read(const unsigned char *value)
{
    body_calls++;
    return value ? 200 + *value : -8;
}

ENTRY int64_t fixture_wide(int64_t value) { body_calls++; return value + INT64_C(1099511627776); }
ENTRY const char *fixture_pointer(void) { body_calls++; return "original"; }
ENTRY void fixture_void(uint64_t *value) { body_calls++; *value = 123; }
ENTRY double fixture_addd(double a, double b) { body_calls++; return a + b; }
ENTRY float fixture_mulf(float a, float b) { body_calls++; return a * b; }
ENTRY int fixture_errno_set(int code) { body_calls++; errno = code; return 7; }
ENTRY int fixture_output(uint64_t *out) { body_calls++; if (out) *out = 5; return 0; }
ENTRY int fixture_mark(int value) { marked += value; return value; }
ENTRY int fixture_marks(void) { return marked; }

struct vg_slot {
    uint64_t start;
    uint64_t end;
};

struct vg_pair {
    uint64_t a;
    double b;
};

ENTRY void fixture_finish(struct vg_slot *slot)
{
    slot->start = 1;
    slot->end = 9;
}

ENTRY struct vg_pair fixture_pair(struct vg_pair pair, double scale)
{
    struct vg_pair result;
    body_calls++;
    result.a = pair.a + 1;
    result.b = pair.b * scale;
    return result;
}

#ifdef _WIN32
static volatile int signal_pending;
#else
static volatile sig_atomic_t signal_pending;

static void fixture_on_signal(int signo)
{
    (void)signo;
    signal_pending = 1;
}
#endif

int main(void)
{
    char line[128];
#ifndef _WIN32
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = fixture_on_signal;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    sigaction(SIGUSR1, &action, NULL);
#endif
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("{\"ready\":true}");
    while (1) {
        char *got = fgets(line, sizeof(line), stdin);
        if (got == NULL) {
            if (signal_pending) {
                signal_pending = 0;
                (void)fixture_target(1, 5);
#ifndef _WIN32
                clearerr(stdin);
#endif
                continue;
            }
            if (feof(stdin)) break;
            if (errno == EINTR) continue;
            break;
        }
        if (signal_pending) {
            signal_pending = 0;
            (void)fixture_target(1, 5);
        }
        if (strncmp(line, "typed", 5) == 0) {
            uint64_t output = 0;
            int64_t wide = fixture_wide(7);
            const char *text = fixture_pointer();
            fixture_void(&output);
            printf("{\"wide\":%" PRId64 ",\"text\":\"%s\",\"output\":%" PRIu64 ",\"body_calls\":%u}\n",
                   wide, text ? text : "NULL", output, body_calls);
            continue;
        }
        if (strncmp(line, "finish", 6) == 0) {
            struct vg_slot slot = {0, 0};
            fixture_finish(&slot);
            printf("{\"end\":%" PRIu64 ",\"body_calls\":%u}\n", slot.end, body_calls);
            continue;
        }
        if (strncmp(line, "output", 6) == 0) {
            uint64_t output = 123;
            int result = fixture_output(&output);
            printf("{\"result\":%d,\"out\":%" PRIu64 ",\"body_calls\":%u}\n",
                   result, output, body_calls);
            continue;
        }
        if (strncmp(line, "slot", 4) == 0) {
            struct vg_slot slot = {0, 0};
            fixture_finish(&slot);
            printf("{\"start\":%" PRIu64 ",\"end\":%" PRIu64 ",\"body_calls\":%u}\n",
                   slot.start, slot.end, body_calls);
            continue;
        }
        if (strncmp(line, "voidnull", 8) == 0) {
            fixture_void(NULL);
            printf("{\"body_calls\":%u}\n", body_calls);
            continue;
        }
        if (strncmp(line, "marks", 5) == 0) {
            printf("{\"marked\":%d,\"body_calls\":%u}\n", fixture_marks(), body_calls);
            continue;
        }
        if (strncmp(line, "pair", 4) == 0) {
            uint64_t a = 0;
            double b = 0.0, scale = 1.0;
            sscanf(line, "pair %" SCNu64 " %lf %lf", &a, &b, &scale);
            struct vg_pair input = {a, b};
            struct vg_pair result = fixture_pair(input, scale);
            printf("{\"a\":%" PRIu64 ",\"b\":%.17g,\"body_calls\":%u}\n",
                   result.a, result.b, body_calls);
            continue;
        }
        if (strncmp(line, "addd", 4) == 0) {
            double a = 0.0, b = 0.0;
            sscanf(line, "addd %lf %lf", &a, &b);
            double result = fixture_addd(a, b);
            printf("{\"result\":%.17g,\"body_calls\":%u}\n", result, body_calls);
            continue;
        }
        if (strncmp(line, "mulf", 4) == 0) {
            float a = 0.0f, b = 0.0f;
            sscanf(line, "mulf %f %f", &a, &b);
            float result = fixture_mulf(a, b);
            printf("{\"result\":%.9g,\"body_calls\":%u}\n", (double)result, body_calls);
            continue;
        }
        if (strncmp(line, "errno", 5) == 0) {
            int code = 0;
            sscanf(line, "errno %d", &code);
            int result = fixture_errno_set(code);
            int saved = errno;
            printf("{\"result\":%d,\"errno\":%d,\"body_calls\":%u}\n", result, saved, body_calls);
            continue;
        }
        uint64_t key = 0;
        unsigned value = 0;
        int result = 0;
        if (sscanf(line, "set %" SCNu64 " %u", &key, &value) == 2)
            fixture_observe(key, value);
        else if (sscanf(line, "clear %" SCNu64, &key) == 1)
            fixture_clear(key);
        else if (sscanf(line, "call %" SCNu64 " %u", &key, &value) == 2)
            result = fixture_target(key, value);
        else if (sscanf(line, "byte %u", &value) == 1) {
            unsigned char byte = (unsigned char)value;
            result = fixture_read(&byte);
        } else if (strncmp(line, "null", 4) == 0)
            result = fixture_read(NULL);
        else if (strncmp(line, "exit", 4) == 0)
            break;
        else
            result = -99;
        printf("{\"result\":%d,\"body_calls\":%u}\n", result, body_calls);
    }
    return 0;
}
