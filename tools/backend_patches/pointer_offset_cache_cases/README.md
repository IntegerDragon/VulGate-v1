# CBMC 6.11.0 pointer-offset cache review and small regression inputs

The adjacent patch changes only `simplify_expr_with_value_set.h` and `.cpp`.
It memoizes the existing value-set scan by the complete L1 SSA expression.
Both a uniform raw offset and failure to find a uniform offset are cached.
It does not select objects, change guards, remove assertions, truncate paths,
or contain application-specific rules.

## Cache semantics and lifetime

The key is the original SSA expression after the existing `remove_level_2()`.
It retains type, object, thread, and frame identity. A cached offset is the
original expression, before conversion to `POINTER_OFFSET`'s result type.
Every positive hit still executes the existing `conditional_cast` and
`simplify_rec`. Every negative hit still executes the existing base-class
`simplify_pointer_offset` fallback. Unknown, invalid, failed-symbol, unknown
offset, differing-offset, and empty-set handling are unchanged.

`simplify(exprt &)` is virtual in CBMC 6.11.0. The patch overrides it, clears
the cache, and activates caching only for that call's dynamic scope. A local
RAII guard restores the previous active state on both normal return and stack
unwinding, including nested calls. Outside this scope, public node methods
perform fresh value-set queries and do not read or populate the cache. A caller
can update the value set or namespace between calls on the same instance,
including direct node calls. During one simplification call, the value set and
namespace must remain stable, as they do at all audited production call sites.

There are eleven production construction sites in this version. Nine create
temporary objects; the two named objects exist only around one `simplify`
call in `symex_goto.cpp:79` and `symex_builtin_functions.cpp:481`. The other
sites are `goto_symex.cpp:36`, `symex_assign.cpp:210`,
`goto_symex_state.cpp:93`, `symex_builtin_functions.cpp:75,170,343`, and
`field_sensitivity.cpp:227,241,653`. `renamedt::simplify` only forwards the
call. State mutation and renaming occur outside these lifetimes.

The L1 symbol branch of `value_sett::get_value_set_rec` reads the existing
object map. The query creates a local result and may extend shared object
numbering, but does not change existing object identities or value-set
entries. The `const` reference alone is not the immutability argument; the
call-site and query-body audit supplies it.

Most recursive simplification uses `simplify_rec`, retaining the cache.
`simplify_expr_array.cpp:158` calls `simplify(tmp_index)` and consequently
clears it again, with the enclosing active state restored on return. This may
lower the hit rate but does not reuse stale data.
No cached map iterator/reference is retained across recursive simplification.

## Validation status

The patch was generated from the original private 6.11.0 source without
modifying that source. `git apply --check` passed. The adjacent manifest
records SHA-256 hashes of both original and patched files and of the patch.
The original toolchain and verifier Python were not changed by this task.
Compilation, symbolic regressions, and application-query measurements of the
current patch are owned by the main task. The standalone C++ regression below
was prepared and run against the preceding patch, where it identified the
public-API regression that motivated the current active-scope correction.

All dependent translation units must be rebuilt after changing the class
layout. Rebuilding only `simplify_expr_with_value_set.cpp` is insufficient.

## Small differential regressions

Run each input with both the frozen baseline binary and the private patched
binary. Use identical paths and flags, first with `--64`, then with `--32`:

```sh
"$CBMC" INPUT.c --64 --bounds-check --pointer-check \
  --pointer-primitive-check \
  --signed-overflow-check --unsigned-overflow-check \
  --unwind 4 --unwinding-assertions --json-ui > OUTPUT.json
```

The variables above denote explicitly selected binary/input/output paths;
keep distinct raw reports and binary hashes for the two binaries. None of
these inputs contains loops, arbitrary address construction, or an exploit.
All C fixture storage is explicitly initialized. CBMC's executable does not
accept `--uninitialized-check`; initialization instrumentation is exercised
separately by the verifier regression suite.

| Input | Expected result | Purpose |
|---|---|---|
| `uniform_offsets.c` | All properties SUCCESS; exit 0 | Two possible objects with one offset, repeated queries and result casts |
| `mixed_offsets.c` | Exactly `mixed-offset counterexample preserved` fails; exit 10 | A negative cache entry must not manufacture a uniform offset |
| `state_updates.c` | All properties SUCCESS; exit 0 | Assignment and branch-join state updates must not reuse an old offset |

Compare the complete property inventory and each property's status, not just
the process exit code. Fail the comparison on unknown status, missing result,
timeout, parse error, unexpected failure, or a changed assertion inventory.
Retain all raw reports. These tests check semantic regressions; they do not
establish a performance gain or guarantee that a particular cache hit occurred.

For a direct C++ unit test, construct a value set and one simplifier, then
simplify a compound expression with repeated L1 pointers and distinct L2
indices. Check uniform, nonuniform, unknown, invalid, failed-symbol, and empty
sets against the original helper. Use different `pointer_offset_exprt`
result types; C casts alone may be simplified outside the node. Update the
same value set between two `simplify` calls on the same instance to exercise
the explicit invalidation boundary. Counting actual cache hits requires a
test-only hook or profiling; `get_value_set` is not virtual, so a subclass
query counter would not intercept it.

## Standalone public-API regression and correction history

`pointer_offset_cache_unit.cpp` implements this check with public
`value_sett::assign`, `insert`, `update_entry`, SSA construction, and simplifier
APIs. It invokes no solver and uses no private-access workaround. Its default
execution includes 24 checks across 32-bit and 64-bit pointer types, plus a
direct-node state-update regression, for 25 checks total:

- Uniform offsets across two objects and repeated L2 versions of one L1 key.
- Different `pointer_offset_exprt` result types in one compound expression.
- Negative numeric offsets; nonuniform, unknown, invalid, failed-object,
  unknown-offset, and empty-set fallback.
- Positive and negative cache invalidation between top-level calls through a
  `simplify_exprt &` base-class reference.
- Different L0 thread and L1 frame identities sharing one source symbol.
- Direct public node calls before and after a value-set update.

The earlier patch with SHA-256
`b2a0a1b5b51cfeb72569ecc6cd095b477f2e5e4d8d74bb05232d493e53bb7ea0`
passed the first 24 checks but returned stale offset 3 instead of 7 after a
direct public node call and update. The original binary returned 7. That
patch is superseded; its patch, manifest, README, and generator are preserved
under the workspace's `work/general-implementation/history/pointer-offset-cache-v1`.
The old unit source, runner, binaries, and raw results are preserved in
`/home/vita/vulgate-offset-cache-unit-20261104-v2`; the copied source hash was
checked against the original report before the test was updated.

The current corrected patch SHA-256 is
`6e7c772e61ad330824938d385f02d4440d90bf75d482325df84bfdec5da7fbfd`.
The workspace runner accepts `--candidate` and `--output`, refuses to reuse an
output directory, builds separate tests against the original and candidate
headers/libraries, and requires all 25 default checks to pass with identical
output. A direct-node regression now fails the complete run. Build logs,
commands, source/library/binary hashes, and raw outputs are retained.

The standalone test verifies observable simplification behavior. It does not
count cache hits or establish a performance benefit. Nested-call restoration
and exception unwinding are covered by the RAII implementation's review;
they do not have dedicated fault-injection tests in this small test program.
