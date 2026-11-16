#include <stdint.h>
#include <stdio.h>
#include <string.h>

unsigned char core_globals[1024];
unsigned char sapi_globals[1024];
static unsigned long long body_calls = 0;

__attribute__((visibility("default"), noinline))
void rfc1867_post_handler(void *content_type_dup, void *arg)
{
    (void)content_type_dup;
    (void)arg;
    body_calls++;
}

int main(void)
{
    char line[64];
    printf("{\"ready\":true}\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 2;
    }
    memset(core_globals, 0, sizeof(core_globals));
    memset(sapi_globals, 0, sizeof(sapi_globals));
    rfc1867_post_handler(0, 0);
    printf("{\"body_calls\":%llu}\n", body_calls);
    fflush(stdout);
    return 0;
}
