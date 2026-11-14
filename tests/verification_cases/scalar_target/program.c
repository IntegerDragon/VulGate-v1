extern void __CPROVER_assert(_Bool, const char *);
extern void __CPROVER_assume(_Bool);
extern unsigned nondet_uint(void);

static int perform_operation(unsigned count) {
    __CPROVER_assert(count <= 4, "target.capacity_contract");
    return (int)count;
}

void verify_service(void) {
    unsigned count = nondet_uint();
    __CPROVER_assume(count <= 8);
    int result = perform_operation(count);
    __CPROVER_assert(result >= -1, "contract.return_domain");
}
