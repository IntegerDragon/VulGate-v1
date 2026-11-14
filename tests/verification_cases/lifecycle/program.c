#include "state.h"
extern unsigned nondet_uint(void);
extern void __CPROVER_assert(_Bool, const char *);

void initialize_work(struct WorkState *state) {
    state->budget = nondet_uint();
    state->remaining = state->budget;
}

int perform_operation(unsigned count) {
    __CPROVER_assert(count <= 4, "target.capacity");
    return 0;
}

void process_event(struct WorkState *state) {
    if (state->remaining == 0)
        return;
    int rc = perform_operation(state->remaining);
    __CPROVER_assert(rc == 0 || rc == -1, "contract.return");
    state->remaining--;
}

void root(void) {
    struct WorkState state;
    initialize_work(&state);
    process_event(&state);
}
