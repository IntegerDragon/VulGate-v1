#include <stdio.h>
#include <string.h>

int vulnerable_copy(const char *input, size_t len)
{
    char buf[16];
    size_t copy_len = len;

    if (copy_len >= sizeof(buf)) {
        fprintf(stderr, "VULN_REACHED len=%zu buffer=%zu\n", len, sizeof(buf));
        copy_len = sizeof(buf) - 1;
    }

    memcpy(buf, input, copy_len);
    buf[copy_len] = '\0';
    return (int)buf[0];
}
