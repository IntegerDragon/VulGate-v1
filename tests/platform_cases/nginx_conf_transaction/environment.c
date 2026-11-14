#include "environment.h"

vg_file_environment vg_env;
ngx_uint_t ngx_dump_config;

/* Single-threaded errno storage is part of the declared C environment. */
int *__errno_location(void)
{
    return &vg_env.error_number;
}

int open(const char *path, int flags, ...)
{
    vg_env.open_attempts++;
    __CPROVER_assert(path == vg_env.expected_path, "environment.open_expected_path");
    __CPROVER_assert(flags == O_RDONLY, "environment.open_read_only");
    __CPROVER_assert(!vg_env.fd_open, "environment.no_overlapping_open");
    if (vg_env.open_fails) {
        vg_env.error_number = EACCES;
        return -1;
    }
    vg_env.fd_open = 1;
    vg_env.acquired++;
    return VG_CONFIG_FD;
}

int fstat(int fd, struct stat *info)
{
    vg_env.fstat_attempts++;
    __CPROVER_assert(fd == VG_CONFIG_FD && vg_env.fd_open,
                     "environment.fstat_live_descriptor");
    if (vg_env.fstat_fails) {
        vg_env.error_number = EIO;
        /* A failed fstat makes no promise to initialize the caller's output. */
        return -1;
    }
    *info = (struct stat) {0};
    info->st_mode = S_IFREG | S_IRUSR;
    info->st_size = (off_t) vg_env.length;
    return 0;
}

ssize_t pread(int fd, void *buffer, size_t size, off_t offset)
{
    size_t available, count, i;
    unsigned char *bytes = buffer;
    vg_env.pread_attempts++;
    __CPROVER_assert(fd == VG_CONFIG_FD && vg_env.fd_open,
                     "environment.pread_live_descriptor");
    __CPROVER_assert(offset >= 0 && offset <= (off_t) vg_env.length,
                     "environment.pread_bounded_offset");
    __CPROVER_assert(size <= sizeof(vg_env.content),
                     "environment.pread_bounded_request");
    if (vg_env.read_mode == VG_READ_ERROR) {
        vg_env.read_failures++;
        vg_env.error_number = EIO;
        return -1;
    }
    available = vg_env.length - (size_t) offset;
    count = size < available ? size : available;
    if (vg_env.read_mode == VG_READ_SHORT && count > 0) {
        count--;
        vg_env.short_reads++;
    }
    for (i = 0; i < count; i++) {
        bytes[i] = vg_env.content[(size_t) offset + i];
    }
    return (ssize_t) count;
}

int close(int fd)
{
    vg_env.close_attempts++;
    __CPROVER_assert(fd == VG_CONFIG_FD && vg_env.fd_open,
                     "environment.close_live_descriptor");
    if (fd != VG_CONFIG_FD || !vg_env.fd_open) {
        vg_env.error_number = EBADF;
        return -1;
    }
    /* Linux releases this valid descriptor before the modeled EIO/EINTR
     * report. The environment has no concurrent close or descriptor reuse.
     * An error report and a release are deliberately separate observations. */
    vg_env.fd_open = 0;
    vg_env.released++;
    if (vg_env.close_mode != 0) {
        vg_env.close_failures++;
        vg_env.error_number = vg_env.close_mode == 1 ? EIO : EINTR;
        return -1;
    }
    return 0;
}
