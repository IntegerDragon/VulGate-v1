#include <stdint.h>
#include <stdio.h>

static unsigned long long body_calls = 0;

__attribute__((visibility("default"), noinline))
void callee(uint64_t key, uint64_t value)
{
    (void)key;
    (void)value;
    body_calls++;
}

__attribute__((visibility("default"), noinline))
void caller(void)
{
    volatile uint64_t available_in = 77;
    callee(1, available_in);
}

int main(void)
{
    char line[64];
    printf("{\"ready\":true}\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 2;
    }
    caller();
    printf("{\"body_calls\":%llu}\n", body_calls);
    fflush(stdout);
    return 0;
}
