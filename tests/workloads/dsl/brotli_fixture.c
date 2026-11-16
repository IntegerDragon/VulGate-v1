#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct BrotliDecoderState {
    unsigned char bytes[256];
} BrotliDecoderState;

static unsigned long long body_calls = 0;

__attribute__((visibility("default"), noinline))
int WriteRingBuffer(BrotliDecoderState *s, void *available_out, void *next_out,
                    void *total_out, int force)
{
    (void)s;
    (void)available_out;
    (void)next_out;
    (void)total_out;
    (void)force;
    body_calls++;
    return 0;
}

__attribute__((visibility("default"), noinline))
void BrotliDecoderDecompressStream(void)
{
    BrotliDecoderState s;
    memset(&s, 0, sizeof(s));
    *(int32_t *)((char *)&s + 132) = 0;
    *(uint64_t *)((char *)&s + 80) = 8;
    *(void **)((char *)&s + 24) = (void *)0;
    *(void **)((char *)&s + 40) = (void *)1;
    volatile uint64_t available_in = 100;
    WriteRingBuffer(&s, 0, 0, 0, 0);
    (void)available_in;
}

int main(void)
{
    char line[64];
    printf("{\"ready\":true}\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {
        return 2;
    }
    BrotliDecoderDecompressStream();
    printf("{\"body_calls\":%llu}\n", body_calls);
    fflush(stdout);
    return 0;
}
