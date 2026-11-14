#include "autoshield.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEMO_BUFFER_SIZE 16

int vulnerable_copy(const char *input, size_t len);

static size_t requested_len(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "poc") == 0) {
        return 64;
    }
    if (argc >= 2 && strcmp(argv[1], "normal") == 0) {
        return 8;
    }
    if (argc >= 2) {
        return (size_t)strtoull(argv[1], NULL, 10);
    }
    return 8;
}

int main(int argc, char **argv)
{
    char payload[128];
    size_t len = requested_len(argc, argv);
    int result;

    memset(payload, 'A', sizeof(payload));
    payload[sizeof(payload) - 1] = '\0';
    if (len > sizeof(payload) - 1) {
        len = sizeof(payload) - 1;
    }

    result = vulnerable_copy(payload, len);
    if (result == SHADOW_BLOCK_RETURN) {
        printf("RESULT BLOCKED code=%d\n", result);
        return 2;
    }

    if (len >= DEMO_BUFFER_SIZE) {
        printf("RESULT OVERFLOW_WRITE value=%d\n", result);
        return 0;
    }

    printf("RESULT OK value=%d\n", result);
    return 0;
}
