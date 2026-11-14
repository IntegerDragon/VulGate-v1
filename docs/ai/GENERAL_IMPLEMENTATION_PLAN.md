# General context-verified mitigation implementation

Active objective (user scope update): implement the method as a general system for **the Linux kernel and Nginx**, replacing the fixture-specific demo. Linux means the kernel, as explicitly confirmed by the user. Native Windows/macOS support, unrelated operating systems and unrelated application targets are not completion requirements. Windows/WSL may remain the local orchestration environment while execution and platform validation target Linux. This document records completion requirements; passing an intermediate test does not complete the objective.

## Required end state

1. **Real program input.** Consume C translation units, build flags/compilation databases, a root harness, environment/resource contracts, and independent target specifications. Program-specific behavior belongs in source/contracts, never verifier branches keyed by example names.
2. **Compiler-backed context.** Preserve actual caller continuations and object state. Discover and identify candidate function entries across translation units; track unresolved call targets and preprocessing/build dependencies.
3. **Return actions.** Bind entry, return value/type, scope and conditions. Check initialized outputs, memory/resource obligations and user-defined protocol contracts. Record qualified regions, refutations, unknowns and unreachable contexts.
4. **Observable policy construction.** Use typed, read-only observation expressions; derive action availability per observation region; support supplied and generated policies with structured counterexample feedback. Check observation evaluation itself.
5. **Whole-policy verification.** Independently establish refusal contracts, PASS preservation, and target coverage over the protected program. Include combinations and repeated invocations; preserve incomplete-solving status.
6. **Lifetime and progress.** Check persistent-state contracts and progress separately. Bounded event tests are not arbitrary-event proofs; induction/closure and progress evidence must state their assumptions and scope.
7. **Evidence reuse.** Bind evidence to sources, build, tool versions, scope, action and contracts. Guard edits reuse only unaffected action results; policy reachability and coverage are rechecked.
8. **Runtime correspondence.** Produce executable policy/instrumented artifacts with a manifest, check type/ABI/observation semantics, test against the verifier and reject stale/mismatched evidence. Integrate existing policy/runtime interfaces where supported.
9. **Usable orchestration.** Provide CLI, documented specification/schema, toolchain discovery, timeouts, structured reports, external generator interface and reproducible setup.
10. **Independent-program validation.** New C programs must run without changing the verifier. Test initialization, ownership/aliasing, normal errors, multiple callers/TUs, loops, persistent events, observation conflicts, weakened guards, unknown external semantics and invalidation. Use benign contract fixtures, not exploit workloads.
11. **Linux kernel and Nginx integration.** Consume real configured project builds and source identities; bind their function/ABI, typed observations and return actions to the verification and runtime interfaces. Validate normal operation, contract-preserving error paths, resource cleanup and lifecycle/progress in actual Nginx and an isolated Linux kernel environment. Existing generic C tests or an unbound hook/module build do not by themselves satisfy this requirement. Do not construct or run exploit workloads.

## Implementation sequence

- Establish a real C verification toolchain and audit its behavior for initialization, resource checks, partial loop expansion and external functions.
- Add `tools/verification/` for specifications, source transformation, backend execution and reports. Preserve existing repository edits.
- Implement context/action/policy proof obligations and general observation synthesis; wire candidate discovery and evidence storage.
- Add lifecycle/progress and deployment/runtime correspondence, then expand independent-program validation and packaging.

CBMC is the initial symbolic C backend because it provides compiler semantics, caller execution, pointer checks, explicit properties and machine-readable results. Backend-specific bounds and limitations remain explicit. The earlier LLVM/KLEE proposal remains a possible additional backend, not a reason to hand-encode program semantics.

## Completion audit

For each requirement above, link implementation and authoritative tests/reports. Any missing, incomplete or indirectly supported requirement keeps the objective active. Tool failures, missing function bodies, timeouts, unsupported constructs and unwinding failures must never produce a proved result.

## Current state

- The 2026-11-05 integrated initialization transformer uses separate compiler-typed result temporaries for shadow-field reads and literal probes. Both model import sites require whole-model roundtrip equality followed by native `--validate-goto-binary` validation and unchanged binary/tool identities. The revision passed 139 serial regressions against the cold-built backend; three actual transport cases also passed after integration. The saved large Nginx resource input had 567 literal-helper call-result type mismatches and is retained as failed historical input. Fresh source-derived application queries, rather than edits to that GOTO file, are required before continuing its fixed-inventory evaluation. These construction checks do not establish application sufficiency.

- A fresh Nginx resource query has now been generated from the original 0..2-byte/five-character root with 18 explicit environment summaries. Both imported models passed equality and native validation in 210.122 seconds; the solver was deliberately not launched at this construction checkpoint. Explicit safety instrumentation and loop unwinding also passed on the experimental fixed-inventory path. A private instruction-streaming reducer then checked the full 2.02 GB frozen export in 106.234 seconds at 51,416 KiB peak RSS, retaining all 366 functions and all 20,798 original typed safety assertions among 72,686 expanded assertions. Its v11 runner integration passed 79 tests and 138 subtests. Full fixed-inventory preparation subsequently completed all 21 stages in 628.331434 seconds, including exact function/symbol identity after loading under both optimization configurations. The inventory contains 45 unwind properties; independent raw-evidence revalidation and paired solver evaluation remain in progress. These construction results do not extend the earlier application safety claim.

- Added explicit, dependency-bound environment function summaries. Exact TU/function definitions retain their declarations and parameter scopes; frozen original/summary bodies, signatures, hashes and assumptions are recorded in every query artifact and the CLI. Baseline, action, protected and conditional PASS queries use the same summaries. Native export, induction and automatic generation with summaries require separate qualification and are explicitly refused by this first interface.
- Added conservative write-only initialization transfer for ordinary struct bit-fields. Original assignments and RHS/address checks remain; no neighbouring shadow bytes are marked initialized. Reachability markers identify deferred transfers, and possible precision-induced initialization failures remain UNKNOWN. Bit-field reads, observable storage and union storage retain their separate requirements.
- Resource-stage regression has 281 distinct tests with latest passing results. A separately captured non-debug Nginx 1.28.0 build supplies the original configuration-file transaction. Under 18 explicit libc/logging boundary summaries and a fixed one-space root, the protected query, conditional PASS query and structural PASS check pass; each symbolic query retains 20,837 properties. Baseline and nondeterministic action queries with the original read path time out, so nonvacuity and complete policy qualification remain unestablished. The 0..2-byte symbolic input domain also remains UNKNOWN. The successful protected result covers the original descriptor/buffer cleanup and context restoration after refusal; it does not establish pread execution coverage, environment/native equivalence or lifecycle induction.

- Previous demo: explicit fixture models and instrumented C replay; retained as design reference.
- Added `tools/verification/`: task/policy schema, typed expression emission, compiler preprocessing, multiple translation units, entry transformation, compiler-derived call graph, actual root/caller execution, obligation classification and content-bound action cache.
- Action queries choose PASS/BLOCK nondeterministically at every invocation; whole-policy queries execute the supplied guards.
- Added alias-aware initialization instrumentation on compiler GOTO IR using Symbolic Shadow Memory and the `symtab2gb` JSON import interface. It covers tested local/global objects, output aliases, fields, array elements, short-circuit reads, string literals and C `_Bool`. Unsupported effects/backend warnings remain UNKNOWN.
- Fixed an audited stock CBMC initialization false positive by replacing that experimental check, rather than suppressing its failures. Standard malloc/free model internals are trusted separately from user object initialization; CBMC resource checks remain active.
- Toolchain: official CBMC 6.11.0 Ubuntu 24.04 package, SHA-256 `b3721aa541038384d7801ea3aeabbcddc3e8845ac8f1cbff637cf8dec7481ac8`; executable fingerprints enter evidence. Source reference commit `820ff0f555b43fb78e0cd9332e498461bd14244b` was inspected to audit model/IR behavior.
- Added compiled observation qualification and structural PASS evidence for supported sequential C. The protected query and an explicitly conditional all-PASS query check definedness; original blocked paths need not pass. Volatile/atomic/floating-point observations, address-representation sensitivity and unsupported guard effects remain UNKNOWN.
- Added target-site reachability probes after preceding harness assumptions. Root-entry reachability alone no longer establishes target non-vacuity; incomplete unwinding never proves a target unreachable.
- Added multi-entry, multi-action observation-table synthesis over a supplied predicate basis. Every candidate is compiled and verified as a complete protected C program; complete decision prefixes generalize refutations, while unsuitable traces exclude only their current candidate. A finite-domain solver distinguishes satisfying tables, infeasible sketches and exhausted budgets.
- Generated table policies use the normal verification CLI. Reports bind candidates, feedback, selected per-region actions, reachability and final evidence. Action cache entries with UNKNOWN obligations are retried; dependencies must stay identical throughout synthesis.
- Hardened orchestration against WSL fingerprint timeouts and preprocessed source pragmas disabling required backend checks. Both produce explicit UNKNOWN outcomes; unsupported evidence never becomes a learned exclusion.
- Added compilation-database/per-unit configuration: ordered native preprocessing, preserved source spelling and working directories, response-file dependencies, unambiguous record selection and separate compilation/linking. Unknown semantic options are rejected instead of discarded. Build metadata and native compiler identity enter evidence; mutable inputs are frozen and changed preprocessed snapshots are rejected.
- Added native/GOTO qualification of fundamental types and representative aggregates. GCC x86-64 signed/unsigned char configurations pass; the tested CBMC 6.11.0/GCC i386 profile has a long-double alignment disagreement and remains UNKNOWN. This qualification does not establish arbitrary layout or machine-code correspondence. Clang execution and other profiles remain unvalidated.
- Candidate target owners are obtained from actual GOTO assertions, retaining the distinction between same-name static functions in separate translation units.
- Added compiler-derived candidate construction: typed entry bindings, parameter/struct observations, compiled conditions, constant return actions, declared catalog limits and root-harness exclusion. Automatic construction expands the finite observation basis after a completed infeasibility result, with whole-program validation and discovery-to-synthesis dependency binding.
- Added an external generator process protocol with request identities, validated sketches, process/output limits, structured syntactic/semantic feedback and preserved attempt artifacts. Included an optional Responses API adapter using a recursive structured-output schema and explicit model selection. Local process and substitute-client tests cover the interface; live-model evaluation is still absent.
- Added joint Cartesian policy families with nonempty action domains per observation region. Fixed-table choices persist across recursive root calls; per-invocation choices may vary. All permitted choices are checked with actual caller contracts. Generated family storage receives actual initialization/write tracking.
- Added conditional action reachability and qualification tied to the entire joint family, separating contract qualification from target coverage. Greedy whole-family expansion preserves a supplied seed and reports inclusion maximality only when every candidate addition is resolved; query budgets, unknowns and changed dependencies retain incomplete status. Arbitrary correlated families and global size optimization are outside this representation.
- Added compiler-typed persistent-state induction through real initializer/event functions. Generated initiation and consecution roots establish a supplied invariant and full logical-field initialization from arbitrary state, supporting any number of completed events without unrolling an event loop. The state audit checks reachable code and policy observations for hidden mutable globals, unframed effects, concurrency and unsupported persistent representations.
- Added separate active-state ranking queries. A nonnegative decreasing integer rank, complete event execution, no event-pruning assumptions and continued driver invocation establish descent to inactivity. Initial input assumptions remain separate. Failed consecution/ranking obligations are not reported as actual reachable execution failures. Program/build/toolchain and expanded-header identities bind all phases; ordinary original-root verification remains a separate evidence item.
- Validation is recorded in the authoritative JUnit report `build/verification/tests.xml` and the user-facing progress package.
- Added a runtime export pipeline using the existing monitor compiler, assembler and VM. Typed observations remain in generated C entry adapters; finite region decisions execute in the VM and typed returns remain in the original functions. Export verifies the actual native source with the VM in the root context, compiles native objects and a static archive, and exhausts the region domain in native self-tests. A caller-pinned manifest binds artifacts, current program/build/toolchain, and runtime/compiler sources. Final application linking and installation remain separate obligations.
- Unsupported initialization effects now receive explicit instruction-level unreachability obligations. Unreachable effects can be discharged; reachable effects, missing properties and incomplete queries retain UNKNOWN. String-literal initialization checks use separate branches, and repeated unconditional symbol reads within one instruction share a check. Task evidence includes configurable pointer object-number bits for larger contexts.
- Pointer encoding is normalized before initialization tracking, updating the backend's allocation-bound symbol and initializer together. A proof-result marker checks that CBMC did not subsequently regenerate the initializer and discard instrumentation. Regression coverage includes initialized static aggregates, missing local writes, nondefault object bits, and deliberately mismatched post-instrumentation encoding.
- Added a private toolchain installer with a pinned official CBMC package, exact Python wheel versions/hashes, a fresh virtual environment, offline input options and a caller-pinned installation manifest. Host Ubuntu/GCC remain explicit prerequisites. WSL invocation now uses direct execution to preserve literal argv; the Windows/WSL installation is checked through a fresh real C verification.
- Added canonical GCC line-marker masking only for syntax parsing, preserving original byte offsets and compiler input. This handles system-header macro expansions inside C expressions. The parser revision passed 239 existing tests on a frozen snapshot.
- Added a generated native assertion adapter (return on true, abort on false), while symbolic queries retain CBMC intrinsic assertions and their original labels. This allows the native main translation unit to be included in the verified source set without redefining CBMC's internal assertion type. A subsequent targeted runtime/setup rerun passed 35 tests.
- Added `tools/application_binding.py`: explicit selection of pinned native objects from the runtime task, preliminary/final GCC links with matching traces, platform link-input and tool/spec/script fingerprints, ELF metadata, and caller-pinned application manifests. It supports independent checks of installed bytes and version labels. The CLI preserves the declared symbolic root and does not equate selected-source membership with coverage of every native-main execution. Application integration validation is recorded separately from the parser regression.
- Added compiler-query binding metadata consumption after symbol resolution and entry-obligation restoration. Exact helper names, shapes, bindings, namespaces and retained references are checked before generated helpers are removed; original functions, addresses and obligations remain. Indirect calls then use compiler value-set proposals and standard fallback with explicit target-set assertions after initialization instrumentation. Every query variant independently qualifies all recorded target checks; missing, failed or incomplete qualification retains UNKNOWN. Generator feedback exports only complete, qualified program counterexamples. These mechanisms use compiler symbols and IR rather than application-specific callback names.

## Still required before completion

Platform integration now includes a policy-enabled Nginx 1.28.0 executable.
Its no-post size-parser/configuration-caller context discharges target,
contracts, initialization, PASS and nonvacuity obligations, including a separate
query through the real VM. Captured object substitution binds the full server
link; an independent freshness check and normal HTTP/configuration/reload/
shutdown checks passed. Its declared root and input bounds still define the
proof scope. The later callback milestone below extends this context to the
optional supplied post callback.
Linux 6.6.1 has 861 captured C recipes and isolated baseline boot/procfs/sysfs/
reboot evidence. The original kstrtouint/ctype context now has a qualified
benign decimal-prefix policy, preserving output state on error, with PASS and
nonvacuity evidence. Its actual-VM query passes, and typed kernel-native
objects have been exported and independently checked. Generic kernel image
binding now preserves the original Kbuild archive inputs, selected-object
postprocessing and independent helper objtool passes. A Linux 6.6.1 image has
passed image identity checks and a diskless QEMU run with the actual VM
self-test, nine original-API policy cases, procfs/sysfs and reboot. The supplied
root remains the proof scope. See `tools/KERNEL_BINDING.md` for the supported
x86-64 non-LTO profile and CLI.
The pinned private frontend now corrects integer-constant-expression handling,
generic pointer qualifiers and generic array decay. Four selected original
kernel units pass native preprocessing and diagnostic GOTO parsing. The
diagnostic still omits unqualified kernel options and is not policy evidence.
Three native options now have explicit contextual correspondence obligations:
automatic local zero initialization, relaxed null-pointer optimization, and
wrapping-overflow optimization premises. The options are retained natively;
dependence on their unmodeled behavior produces UNKNOWN, not a native
counterexample. Native execution and actual VM export exercise this path.
The selected x86-64 code-generation profile is retained in native compilation
and ABI probing; 820 full recipes are now parser-admitted. Strict flexible
arrays are contextually admitted when fixed trailing-array access/escape is
unreachable; full subobject provenance remains open. Native compiler queries
for object size and constancy now receive explicit correspondence obligations.
GNU source-locator syntax support preserves the original compiler bytes. The
kernel runtime archive retains its historical BUILT_FOR_GUEST_VALIDATION and
PENDING_KERNEL_GUEST fields. The later image manifest and separate guest report
record the completed linking and execution; the export is not rewritten.
See `docs/human/PLATFORM_INTEGRATION.md`. The objective remains active.

The 2026-11-04 callback refresh qualifies both platform chains with the same
frozen implementation. Nginx's original size-setter/parser root now includes
the optional supplied `record_post` callback and arbitrary byte strings of
length 0--4. It discharges all 141 per-TU compiler-query entries, including nine
entry markers restored through compiler-resolved typed bindings, and all
target, caller-contract, initialization, structural PASS and nonvacuity
obligations. The protected query qualifies 13 target-set checks; the actual-VM
query qualifies 14. Its complete captured link, byte check and eight service
checks pass. Linux retains the original decimal kstrtouint root, at most four
arbitrary bytes followed by NUL, and the benign leading-plus rule. All 99 query
entries and policy/actual-VM obligations pass. Independent Kbuild, objtool,
image identity and isolated guest execution also pass, with two VM regions,
nine API cases and 806 archive members. Both runs retain the original build
options and declared roots under the tested GCC/x86-64/Linux non-LTO profile.

Compiler-query recognition includes parenthesized builtin use. A native GCC
differential audit demonstrated that the previous lexical gap could incorrectly
qualify a constant query; the corrected checker retains UNKNOWN for that reached
query and separately records its abstract-model result. Query bindings resolve
GNU inline and asm redirections without source-name guesses. Unused static
union-bearing objects receive deferred initialization qualification only for
strictly inert values; no shadow bytes are marked initialized, and actual
access still requires union semantics. Structural PASS obligations use operation
content plus occurrence identity, preserving duplicate obligations across
library SKIP removal and restored entry markers. Native marker removal preserves
control flow with a void expression under the original warning-as-error flags.

The optional post-callback milestone is complete for that supplied root.
Consuming generated binding metadata preserves all 141 query records and nine
restored entry markers while reducing Nginx's address set from 135 to the
original three and its broad compatible post targets from 65 to the original
two. Compiler value-set refinement plus contextual target-set obligations
qualifies the reached callback. The harness checks successful callback count,
error/repeated-setting paths that skip the callback, and initialized size input.
The earlier metadata-only and interrupted callback runs remain historical
UNKNOWN results; they are not included in the completed milestone.

Authoritative evidence is in the workspace `outputs/回调支持版/`, with its
continuation record at `work/general-implementation/callback-delivered-next.md`.
The frozen-source reports `both-platforms-callback-final.xml` (307 passing
tests) and `indirect-feedback-checks.xml` (63 passing tests) contain 357 distinct
passing tests, with no failures, errors or skips. Independent archive-byte and
source-extraction/CLI checks pass. The separate callback preservation audit
covers all five Nginx query variants: original ASSERT/ASSUME multisets are
preserved and additions are adjacent target ASSERT(false)/ASSUME(false) pairs.
That audit establishes multiset preservation, not a separate control-flow
equivalence proof. The source archive SHA-256 is
`22ed34b3faffc15484db6a589df69b284c3c719d3715ef489a8f4cf509a450dc`;
the evidence archive SHA-256 is
`f8cf3d2489452bd5cb4178976b42acd08bae63dc6594992c48f987906a75e796`.

The next implementation priority is real resource transactions and explicit
environment contracts in Linux-kernel and Nginx contexts, followed through
lifecycle runtime validation. Extend the supplied roots to allocation,
ownership transfer, cleanup and repeated-event state transitions, with the
required external-state and scheduling assumptions represented in contracts.
Broader callback/state contexts, general union storage, persistent heap and
external-state induction, kernel concurrency, remaining build profiles and
live generator evaluation remain open. The completed callback milestone does
not complete these requirements or the general implementation objective.

- Build-option, source-location/type/ABI binding required by the selected Linux kernel and Nginx configurations. Compilation-database/per-TU input support is implemented for the documented subset. The observed i386 backend layout incompatibility remains UNKNOWN; unrelated compiler/OS expansion is not a prerequisite for this scoped objective.
- Broader correspondence support beyond the qualified sequential, layout-insensitive C subset, and runtime correspondence.
- Broader automatic observation/entry/action discovery, richer basis refinement and live external-model evaluation. Global state, fixed arrays and bounded interprocedural entry-state translations are now implemented and independently tested; more precise alias/effect/return summaries and recursive/loop transformations remain. Compiler-backed automatic construction and an executable external-generator/Responses interface are implemented for the documented scope.
- Broader persistent-heap/external-state induction and progress contracts beyond the implemented closed integer/aggregate state domain. Induction and scalar ranking now cover arbitrary event counts in that domain, with complete per-event execution and stated scheduling premises.
- Linux-kernel and Nginx runtime contexts, typed hook/adaptor correspondence, real build and lifecycle integration, and scalability validation. The GCC/ELF application linker and installed-file checker are implemented for the declared root scope; version labels identify pinned bytes. This satisfies artifact binding within the supported profile; it does not attest a running process or remove separate environment-contract and compiler-trust assumptions.
- Initialization/alias/lifetime semantic audits, dependency race checks, reproducible Linux execution environments and final packaging for these two targets. Additional unrelated host profiles are not required. The private pinned setup covers the tested Windows/WSL orchestration profile; it does not provision an entire operating-system image.

These remaining requirements keep the original complete-implementation objective active. The CLI reports incomplete overall qualification even when individual harness obligations pass.
