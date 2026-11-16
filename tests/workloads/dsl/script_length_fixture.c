#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct ScriptEngine {
    void *ip;
    void *pos;
    void *end;
} ScriptEngine;

static unsigned long long body_calls = 0;

__attribute__((visibility("default"), noinline))
int64_t ngx_http_script_check_length(ScriptEngine *e, uint64_t len)
{
    if (e->end == NULL) {
        return 0;
    }
    if ((uint64_t)((char *)e->end - (char *)e->pos) < len) {
        body_calls++;
        return -1;
    }
    body_calls++;
    return 0;
}

int main(void)
{
    char line[64];
    char buffer[64];
    ScriptEngine engine;
    memset(&engine, 0, sizeof(engine));
    engine.pos = buffer;
    engine.end = buffer + sizeof(buffer);
    printf("{\"ready\":true}\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 2;
    }
    int64_t enough = ngx_http_script_check_length(&engine, 10);
    int64_t too_long = ngx_http_script_check_length(&engine, 100);
    printf("{\"enough\":%lld,\"too_long\":%lld,\"body_calls\":%llu}\n",
           (long long)enough, (long long)too_long, body_calls);
    fflush(stdout);
    return 0;
}
