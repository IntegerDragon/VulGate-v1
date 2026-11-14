#include <ngx_config.h>
#include <ngx_core.h>

extern unsigned nondet_uint(void);
extern unsigned char nondet_uchar(void);
extern _Bool nondet_bool(void);
extern void __CPROVER_assume(_Bool);
extern void __CPROVER_assert(_Bool, const char *);

static unsigned post_calls;

static char *record_post(ngx_conf_t *cf, void *post, void *data)
{
    (void)cf;
    (void)post;
    __CPROVER_assert(*(size_t *)data != NGX_CONF_UNSET_SIZE,
                     "contract.post_receives_initialized_size");
    post_calls++;
    return NGX_CONF_OK;
}

/* Benign configuration rule: disable the M/m unit. The real Nginx caller
 * must report a parse error, preserve its unset sentinel and skip its post
 * callback. PASS cases retain ordinary parsing and duplicate detection.
 * All byte strings of length 0..4 are symbolic, with explicit live storage.
 */
void root(void)
{
    u_char text[4] = {nondet_uchar(), nondet_uchar(), nondet_uchar(), nondet_uchar()};
    unsigned length = nondet_uint();
    __CPROVER_assume(length <= sizeof(text));
    ngx_str_t values[2] = {{0, NULL}, {length, text}};
    ngx_array_t args = {0};
    ngx_conf_t cf = {0};
    ngx_command_t command = {0};
    ngx_conf_post_t post = {record_post};
    size_t slot = NGX_CONF_UNSET_SIZE;
#ifdef VG_TEST_POST_CALLBACK
    _Bool with_post = nondet_bool();
#else
    _Bool with_post = 0;
#endif
    args.elts = values;
    cf.args = &args;
    command.post = with_post ? &post : NULL;
    post_calls = 0;
    char *result = ngx_conf_set_size_slot(&cf, &command, &slot);
    _Bool forbidden = length != 0 && (text[length - 1] == 'M' || text[length - 1] == 'm');
    __CPROVER_assert(!forbidden || result != NGX_CONF_OK, "target.no_mb_unit");
    if (result == NGX_CONF_OK) {
        __CPROVER_assert(slot != NGX_CONF_UNSET_SIZE, "contract.success_initializes_slot");
        __CPROVER_assert(post_calls == (unsigned)with_post, "contract.success_post_count");
        size_t before = slot;
        char *duplicate = ngx_conf_set_size_slot(&cf, &command, &slot);
        __CPROVER_assert(duplicate != NGX_CONF_OK, "contract.duplicate_rejected");
        __CPROVER_assert(slot == before, "contract.duplicate_preserves_slot");
        __CPROVER_assert(post_calls == (unsigned)with_post, "contract.duplicate_skips_post");
    } else {
        __CPROVER_assert(slot == NGX_CONF_UNSET_SIZE, "contract.error_keeps_unset");
        __CPROVER_assert(post_calls == 0, "contract.error_skips_post");
    }
}
