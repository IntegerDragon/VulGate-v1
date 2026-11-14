#include "operation.h"
extern void __CPROVER_assert(_Bool, const char *);

int operation(unsigned count) {
    const char *source = __FILE__;
    __CPROVER_assert(source[0] == 's', "contract.relative_source_name");
    __CPROVER_assert(count <= LIMIT, "target.capacity");
    return (int)count;
}
