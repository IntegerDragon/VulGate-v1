#include "operation.h"
extern unsigned nondet_uint(void);
extern void __CPROVER_assert(_Bool, const char *);
extern void __CPROVER_assume(_Bool);

void root(void) {
    unsigned count = nondet_uint();
    __CPROVER_assume(count <= 8);
    int result = operation(count);
    __CPROVER_assert(result == -1 || result == (int)count, "contract.result");
}
