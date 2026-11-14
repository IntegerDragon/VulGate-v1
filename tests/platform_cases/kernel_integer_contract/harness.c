/* Benign configuration rule: decimal values may not begin with '+'. */
#include <linux/errno.h>
#include <linux/kstrtox.h>

extern unsigned char nondet_uchar(void);
extern void __CPROVER_assert(_Bool, const char *);

void root(void)
{
    char text[5] = {0};
    unsigned int value = 0x12345678u;
    int rc;
    unsigned int i;

    for (i = 0; i < 4; ++i)
        text[i] = nondet_uchar();
    rc = kstrtouint(text, 10, &value);
    __CPROVER_assert(text[0] != '+' || rc < 0, "target.no_plus_prefix");
    __CPROVER_assert(rc >= 0 || value == 0x12345678u, "contract.error_preserves_output");
    __CPROVER_assert(rc != 0 || value <= 9999u, "contract.decimal_range");
}
