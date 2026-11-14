extern _Bool nondet_bool(void);
extern void configure(_Bool);
extern int handle(void);
extern void __CPROVER_assert(_Bool, const char *);

void root(void) {
    _Bool value = nondet_bool();
    configure(value);
    int result = handle();
    __CPROVER_assert(value ? result == -1 : result == 0, "contract.result");
}
