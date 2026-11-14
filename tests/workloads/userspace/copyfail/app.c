/*
 * copyfail workload – demonstrates AutoShield blocking the CVE-2026-31431
 * page-cache write primitive.
 *
 * Usage:
 *   copyfail_app normal   → len=4, ESN at offset 0 (benign)  → PASS
 *   copyfail_app poc      → len=60, ESN at offset 56 (attack) → BLOCK
 *   copyfail_app <N>      → len=N, explicit
 */
#include "autoshield.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int patch_cache(const char *payload, size_t len);

static size_t requested_len(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "poc") == 0)
        return 60;   /* uid_offset(~56) + 4 – targets /etc/passwd UID cache */
    if (argc >= 2 && strcmp(argv[1], "normal") == 0)
        return 4;    /* benign self-test: ESN at offset 0 */
    if (argc >= 2)
        return (size_t)strtoull(argv[1], NULL, 10);
    return 4;
}

int main(int argc, char **argv)
{
    char payload[256];
    size_t len = requested_len(argc, argv);
    int result;

    memset(payload, 'X', sizeof(payload));
    payload[sizeof(payload) - 1] = '\0';

    printf("[*] copyfail_workload  mode=%s  patch_cache(payload, %zu)\n",
           argc >= 2 ? argv[1] : "default", len);

    result = patch_cache(payload, len);

    if (result == SHADOW_BLOCK_RETURN) {
        printf("[!] AUTOSHIELD BLOCKED the call (result=%d)\n", result);
        return 2;
    }

    if (len > 4)
        printf("[+] ATTACK SUCCEEDED: ESN written to offset %zu of victim cache\n",
               len - 4);
    else
        printf("[+] OK: benign ESN write at offset 0 (primitive verified)\n");

    return 0;
}
