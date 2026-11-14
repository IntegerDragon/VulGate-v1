/* Exercise the original kernel API with ordinary configuration strings. */
#include <linux/errno.h>
#include <linux/kstrtox.h>
#include <linux/printk.h>

int vulgate_kernel_policy_probe(void);

int vulgate_kernel_policy_probe(void)
{
    static const struct {
        const char *text;
        int status;
        unsigned int value;
    } cases[] = {
        { "0", 0, 0 }, { "42", 0, 42 }, { "9999", 0, 9999 },
        { "+0", -EINVAL, 0x12345678u }, { "+42", -EINVAL, 0x12345678u },
        { "", -EINVAL, 0x12345678u }, { "x", -EINVAL, 0x12345678u },
        { "-1", -EINVAL, 0x12345678u }, { "12x", -EINVAL, 0x12345678u },
    };
    unsigned int i;
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        unsigned int value = 0x12345678u;
        int rc = kstrtouint(cases[i].text, 10, &value);
        if (rc != cases[i].status || value != cases[i].value) {
            pr_err("VULGATE_KERNEL_POLICY_CASE:%u:FAIL:%d:%u\n", i, rc, value);
            return -EINVAL;
        }
        pr_info("VULGATE_KERNEL_POLICY_CASE:%u:PASS\n", i);
    }
    return 0;
}
