/*
 * copyfail workload – userspace simulation of CVE-2026-31431 primitive.
 *
 * In the real kernel path, authencesn writes a 4-byte ESN at byte offset
 * (splice_len - 4) inside the victim file's page cache.  When splice_len == 4
 * the write lands at offset 0 (harmless self-test).  When splice_len is large
 * (e.g. uid_offset + 4 into /etc/passwd) the write escalates privilege.
 *
 * This userspace model represents that as patch_cache(payload, splice_len):
 *   - len == 4  → benign (ESN at offset 0, verification step)
 *   - len  > 4  → attack (ESN targets a sensitive offset)
 *
 * AutoShield hooks this function and blocks calls where len > 4.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static char simulated_cache[256];

int patch_cache(const char *payload, size_t len)
{
    if (len == 0 || len > sizeof(simulated_cache))
        return -1;

    memcpy(simulated_cache, payload, len);
    fprintf(stderr,
            "PATCH_CACHE: wrote %zu bytes; ESN landed at offset %zu of victim cache\n",
            len, len >= 4 ? len - 4 : (size_t)0);
    return 0;
}
