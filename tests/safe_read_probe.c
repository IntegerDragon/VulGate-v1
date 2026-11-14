#include "autoshield.h"

#include <stdint.h>
#include <stdio.h>

int main(void)
{
    uint8_t value = 0;
    int rc = safe_read(&value, (const void *)(uintptr_t)1, sizeof(value));
    printf("safe_read_invalid rc=%d\n", rc);
    return rc == 0 ? 1 : 0;
}
