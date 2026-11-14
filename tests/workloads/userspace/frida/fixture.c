/* Benign arithmetic fixture: the counter proves whether the body ran. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>

#ifdef _WIN32
#define ENTRY __declspec(dllexport) __attribute__((noinline))
#else
#define ENTRY __attribute__((visibility("default"), noinline))
#endif

static unsigned body_calls;
static volatile uint64_t observed_sink;

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

int main(void)
{
    char line[128];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("{\"ready\":true}");
    while (fgets(line, sizeof(line), stdin)) {
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
