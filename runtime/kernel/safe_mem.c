#include "../autoshield.h"

#include <linux/errno.h>
#include <linux/uaccess.h>

int safe_read(void *dst, const void *src, size_t len)
{
	if (!dst || !src)
		return -EINVAL;

	return copy_from_kernel_nofault(dst, src, len);
}
