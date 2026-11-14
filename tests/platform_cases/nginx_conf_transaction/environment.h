#ifndef VG_NGINX_CONF_TRANSACTION_ENVIRONMENT_H
#define VG_NGINX_CONF_TRANSACTION_ENVIRONMENT_H

#include <ngx_config.h>
#include <ngx_core.h>

extern unsigned nondet_uint(void);
extern unsigned char nondet_uchar(void);
extern _Bool nondet_bool(void);
extern void __CPROVER_assume(_Bool);
extern void __CPROVER_assert(_Bool, const char *);

enum { VG_CONFIG_FD = 73, VG_READ_FULL = 0, VG_READ_ERROR = 1, VG_READ_SHORT = 2 };

typedef struct {
    unsigned char content[2];
    unsigned length;
    const char *expected_path;
    _Bool open_fails;
    _Bool fstat_fails;
    unsigned read_mode;
    unsigned close_mode;
    int error_number;
    _Bool fd_open;
    unsigned open_attempts;
    unsigned acquired;
    unsigned fstat_attempts;
    unsigned pread_attempts;
    unsigned read_failures;
    unsigned short_reads;
    unsigned close_attempts;
    unsigned close_failures;
    unsigned released;
} vg_file_environment;

extern vg_file_environment vg_env;

#endif
