extern void __CPROVER_assert(_Bool, const char *);
extern void __CPROVER_assume(_Bool);
extern unsigned nondet_uint(void);

int process_count(unsigned count) {
    __CPROVER_assert(count <= 4, "target.capacity");
    return 0;
}

void root(void) {
    unsigned count = nondet_uint();
    __CPROVER_assume(count <= 8);
    int first = process_count(count);
    int second = process_count(count);
    __CPROVER_assert(count <= 4 ? first == 0 : first < 0, "contract.first_result");
    __CPROVER_assert(count <= 4 ? second == 0 : second < 0, "contract.second_result");
    __CPROVER_assert(first == second, "contract.stable_return");
}
