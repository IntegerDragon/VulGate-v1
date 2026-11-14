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
