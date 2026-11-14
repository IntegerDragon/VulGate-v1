# Persistent-state induction and progress

`initialize_work` initializes an arbitrary unsigned 32-bit work budget.
`process_event` calls the real operation, checks its return convention and
decreases remaining work. The policy returns -1 when the operation's count is
greater than 4. The program uses capacity assertions and ordinary scalar state.

```sh
python -m tools.verification tests/verification_cases/lifecycle/task.json \
  --lifecycle tests/verification_cases/lifecycle/contract.json \
  --policies tests/verification_cases/lifecycle/policies.json \
  --output build/verification/lifecycle
```

Add `--toolchain /path/to/toolchain.json` when needed. Expected successful fields
are `lifecycle_status: PROVED_INDUCTIVELY` and `progress_status: PROVED_DESCENT`.
Overall status remains UNKNOWN, exit code 2, and deployment readiness is false
while executable runtime correspondence remains pending.

The JSON invariant is `state.remaining <= state.budget`, the active condition is
`state.remaining > 0`, and the rank is `state.remaining`. The verifier generates
three separate C roots and executes the real program functions:

1. Initialize a fresh state, check every scalar leaf's definedness, and assert
   the invariant.
2. Start with an arbitrary compiler-typed state, assume the invariant, run one
   event, and check the invariant, target, contracts and definedness again.
3. Start with an arbitrary invariant state that is active, run one event, and
   check a nonnegative, strictly decreasing rank unless the new state is inactive.

This proves closure for any number of completed events. It does not unroll an
event loop up to `task.unwind`: that bound applies inside the initializer/event
functions, and any insufficient expansion makes the relevant proof UNKNOWN.
The budget is symbolic over the compiler's unsigned type, not capped at 8.

An always-return policy at `process_event` preserves the state invariant and
covers the target, but fails the proposed progress measure because remaining
work does not decrease. A failing inductive step may start from an invariant
state that is not actually reachable; its status is `NOT_INDUCTIVE`, not a claim
that a concrete lifecycle execution violates the property.

The state audit currently covers integer/Boolean/enum leaves, structs and fixed
arrays. It rejects persistent pointers/unions/floating state, mutable globals
outside the state object, unresolved effects, asynchronous execution and
unframed pointer sources. Per-event allocations must be discharged by cleanup
checks. The progress conclusion additionally requires event execution without
pruning assumptions and a driver that keeps invoking events while active.
