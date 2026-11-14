#include <stdint.h>

static unsigned victim_calls;

__attribute__((visibility("default")))
int preload_target(int value)
{
    victim_calls++;
    return 100 + value;
}

__attribute__((visibility("default")))
int preload_output(int *out)
{
    victim_calls++;
    if (out) {
        *out = 5;
    }
    return 0;
}

__attribute__((visibility("default")))
unsigned preload_calls(void)
{
    return victim_calls;
}

__attribute__((visibility("default")))
int preload_observe(int key, int value)
{
    (void)key;
    (void)value;
    return 0;
}

__attribute__((visibility("default")))
int preload_checked(int key)
{
    return 1000 + key;
}

__attribute__((visibility("default")))
int preload_recurse(int depth)
{
    if (depth <= 0) {
        return 0;
    }
    return 1 + preload_recurse(depth - 1);
}
