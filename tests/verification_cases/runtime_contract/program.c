#include "program.h"
extern void __CPROVER_assert(_Bool, const char *);

int apply(const struct Request *request) {
    __CPROVER_assert(request && request->amount >= 0 && request->amount <= request->capacity,
                     "target.capacity");
    return request->amount;
}

int handle(const struct Request *request) {
    int result = apply(request);
    __CPROVER_assert(result >= -2, "contract.return");
    return result;
}

void mark_pending(unsigned count, unsigned *marked) {
    __CPROVER_assert(count <= 4, "target.mark");
    *marked = 1;
}
