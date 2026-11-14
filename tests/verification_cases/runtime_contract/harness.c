#include "program.h"
extern int nondet_int(void);
extern unsigned nondet_uint(void);
extern _Bool nondet_bool(void);
extern void __CPROVER_assert(_Bool, const char *);

void root(void) {
    struct Request request = {nondet_int(), nondet_uint()};
    handle(nondet_bool() ? &request : 0);
    unsigned marked = 0;
    mark_pending(nondet_uint(), &marked);
    __CPROVER_assert(marked <= 1, "contract.output");
}
