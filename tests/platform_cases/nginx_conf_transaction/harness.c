#include "environment.h"

static void transaction(_Bool fail_metadata)
{
    unsigned i;
    u_char filename_data[] = "transaction.conf";
    ngx_str_t filename = {sizeof(filename_data) - 1, filename_data};
    ngx_conf_file_t previous = {0};
    ngx_array_t args = {0};
    ngx_log_t log = {0};
    ngx_conf_t cf = {0};

    vg_env = (vg_file_environment) {0};
    vg_env.length = nondet_uint();
    __CPROVER_assume(vg_env.length <= sizeof(vg_env.content));
    for (i = 0; i < sizeof(vg_env.content); i++) {
        vg_env.content[i] = nondet_uchar();
        __CPROVER_assume(vg_env.content[i] == ' ' || vg_env.content[i] == '\t'
                         || vg_env.content[i] == '\r' || vg_env.content[i] == '\n'
                         || vg_env.content[i] == '}');
    }
    vg_env.expected_path = (const char *) filename_data;
    vg_env.open_fails = fail_metadata ? 0 : nondet_bool();
    vg_env.fstat_fails = fail_metadata;
    vg_env.read_mode = nondet_uint();
    __CPROVER_assume(vg_env.read_mode <= VG_READ_SHORT);
    vg_env.close_mode = nondet_uint();
    __CPROVER_assume(vg_env.close_mode <= 2);

    ngx_dump_config = 0;
    log.log_level = NGX_LOG_NOTICE;
    cf.log = &log;
    cf.args = &args;
    cf.conf_file = &previous;

    /* Original Nginx owns the temporary buffer and descriptor transaction.
     * malloc/free remain the standard library model, including allocation
     * failure and the verifier's original memory-cleanup properties. */
    char *result = ngx_conf_parse(&cf, &filename);

    __CPROVER_assert(result == NGX_CONF_OK || result == NGX_CONF_ERROR,
                     "contract.parse_result_domain");
    __CPROVER_assert(cf.conf_file == &previous,
                     "contract.previous_configuration_restored");
    __CPROVER_assert(vg_env.open_attempts == 1,
                     "contract.one_open_attempt");
    __CPROVER_assert(vg_env.acquired == (unsigned) !vg_env.open_fails,
                     "contract.open_failure_acquires_nothing");
    __CPROVER_assert(vg_env.fstat_attempts == vg_env.acquired,
                     "contract.metadata_once_per_acquisition");
    __CPROVER_assert(vg_env.close_attempts == vg_env.acquired,
                     "contract.close_once_per_acquisition");
    __CPROVER_assert(vg_env.released == vg_env.acquired && !vg_env.fd_open,
                     "contract.descriptor_released_even_on_close_error");
    __CPROVER_assert(vg_env.pread_attempts <= 1,
                     "contract.at_most_one_bounded_read");
    __CPROVER_assert(!vg_env.open_fails || result == NGX_CONF_ERROR,
                     "contract.open_failure_is_error");
    __CPROVER_assert(vg_env.close_failures == 0 || result == NGX_CONF_ERROR,
                     "contract.close_failure_is_error");
    __CPROVER_assert((vg_env.read_failures == 0 && vg_env.short_reads == 0)
                     || result == NGX_CONF_ERROR,
                     "contract.read_failure_is_error");
    __CPROVER_assert(vg_env.length == 0 || result == NGX_CONF_ERROR,
                     "target.reject_nonempty_configuration");
}

void root(void)
{
    /* This task explicitly supplies successful metadata for acquired files. */
    transaction(0);
}

void root_fstat_failure(void)
{
    /* Separate diagnostic: open succeeds, fstat fails without initializing
     * file.info. Original Nginx continues. No initialization premise is added
     * and no allocation-success assumption hides another cleanup branch. */
    transaction(1);
}
