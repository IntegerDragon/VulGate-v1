#include <stdint.h>

static unsigned long long body_calls;

__attribute__((visibility("default"), noinline))
int target_fn(int value)
{
    body_calls++;
    return 100 + value;
}

__attribute__((visibility("default")))
unsigned long long target_body_calls(void)
{
    return body_calls;
}
