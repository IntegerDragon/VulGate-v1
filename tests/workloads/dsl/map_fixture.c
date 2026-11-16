#include <stdint.h>
#include <stdio.h>

static unsigned long long body_calls = 0;

__attribute__((visibility("default"), noinline))
void observe_limit(uint64_t key, uint64_t value)
{
    (void)key;
    (void)value;
}

__attribute__((visibility("default"), noinline))
int target_fn(uint64_t key, uint64_t value)
{
    (void)key;
    (void)value;
    body_calls++;
    return 0;
}

int main(void)
{
    char line[64];
    printf("{\"ready\":true}\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 2;
    }
    observe_limit(1, 100);
    int blocked = target_fn(1, 101);
    int passed = target_fn(1, 101);
    printf("{\"blocked\":%d,\"passed\":%d,\"body_calls\":%llu}\n",
           blocked, passed, body_calls);
    fflush(stdout);
    return 0;
}
