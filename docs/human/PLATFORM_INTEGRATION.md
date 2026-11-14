# Linux kernel and Nginx integration

The current platform work uses Nginx 1.28.0 and Linux 6.6.1, built from versioned
upstream archives. These are fixed validation versions, not claims about the
latest available releases. The archive SHA-256 values and HTTPS origins are
recorded; release signatures have not been verified.

## Capture a configured userspace build

Run on the same Linux host as the build (WSL is supported):

```sh
python3 -m tools.build_capture \
  --output /absolute/new-capture-directory \
  --cwd /absolute/configured-project \
  --compiler gcc -- make -j4 'CC={cc}'
```

Use a fresh configured build so all relevant object compilations execute.
Configure with the real compiler first; capture the actual build afterwards.
The wrapper forwards the original arguments literally. Parallel invocations
write separate records. The collector checks completion, source and output
fingerprints, response files and the selected compiler before publishing
`compile_commands.json`. Failed builds and no-op builds do not qualify.
Compiler environment variables that would be lost from the database must be
expressed as explicit arguments. Use a new output directory for every run.

`CAPTURED` means the build completed and its compiler arguments were recorded.
Verification separately qualifies options, preprocesses the selected sources,
checks types/ABI, and binds their expanded content. Capture does not certify
header immutability, arbitrary compiler flags, every program path or a policy.
The `-pipe` option is retained in provenance and classified as compiler-stage
transport; it has no C/preprocessor/target-ABI effect.

## Native verification environment

`tools.setup_verification` installs the pinned CBMC package and locked Python
dependencies into a new private prefix. On minimal Ubuntu installations without
`ensurepip`, it uses the host pip's `--python` mode to populate a private venv.
It does not install packages into the host interpreter. The completed setup has
an independently checkable manifest pin. Errors now include captured stdout as
well as stderr, including Ubuntu's missing-venv diagnostics.

The native Ubuntu 24.04 / GCC x86-64 setup was installed and independently
checked. The earlier Windows/WSL setup remains a supported orchestration path.

## Nginx contexts

`tests/platform_cases/nginx_size_contract/prepare.py` creates task paths from an
actual Nginx compilation database. The task uses the original `ngx_parse.c`,
`ngx_string.c` and `ngx_conf_file.c`; their implementation is not copied into a
replacement model. Its benign policy disables the `M`/`m` size suffix.
The symbolic root supplies all byte strings of length 0 through 4 and checks the
real `ngx_conf_set_size_slot` caller's sentinel, result and duplicate behavior.
`--with-post-callback` adds an optional real post callback as a separate context.
Neither context implies coverage of every Nginx caller or every input length.

`runtime_check.py` runs a selected Nginx executable on a temporary loopback port.
It checks configuration acceptance, GET/HEAD/404, repeated keepalive requests,
graceful reload and shutdown. With `--expect-unit-block`, it additionally expects
the unit policy and verifies that a rejected reload preserves serving workers.
The no-post context now discharges target coverage, caller contracts,
initialization, PASS correspondence and nonvacuity. Runtime export also verifies
the actual VM and generated adapters in that context, then compiles native
objects and exhaustively tests their finite decision regions. The full captured
Nginx executable has been relinked with those three verified translation units
and the VM helpers; its manifest passed a separate freshness check.

Both the original executable and the policy-enabled executable passed normal
GET/HEAD/404 requests, 20 keepalive requests, reload and graceful shutdown.
With the policy enabled, `client_body_buffer_size 2m` is rejected and a rejected
reload preserves the existing serving workers. This directive uses
`ngx_conf_set_size_slot`; `client_max_body_size` uses `ngx_conf_set_off_slot` and
is not an appropriate test of this policy. The initial runtime test selected
the latter directive; that test mismatch has been corrected and both binaries
rerun with the same corrected runner.

The symbolic optional-post-callback context remains a separate scalability
obligation. No result here covers every Nginx caller, all input lengths, all
server histories, asynchronous state changes or arbitrary dynamic modules.
The application status is `LINKED_WITH_HARNESS_EVIDENCE`; overall deployment
readiness remains false.

## Isolated Linux kernel environment

Linux 6.6.1 was built as a minimal x86-64 kernel with modules, kprobes, procfs,
sysfs and a serial console. Its own compilation-database generator recovered
861 C compilation commands from the completed build. Several kernel-specific
flags are not qualified by the verifier yet; they must not be silently dropped.

`tests/platform_cases/kernel_guest/run.py` builds a small static init program,
packages a `newc` initramfs and boots a caller-selected kernel in QEMU TCG. The
guest has no disks or network. It checks kernel identity, procfs/sysfs and then
reboots; `-no-reboot` lets the runner observe normal emulator termination.
Source, config, kernel, initramfs and emulator hashes are recorded. This baseline
has passed. Final kernel object/link binding, concurrency/resource contracts and
policy-enabled guest validation remain required.

Native preprocessing of the original `lib/cmdline.c`, `lib/ctype.c`,
`lib/kstrtox.c` and `lib/vsprintf.c` completed with the actual kernel options.
A diagnostic GOTO parse originally rejected the latter two at `GENMASK` in
`include/linux/find.h`. The separate C frontend correction now accepts all four
original units. This diagnostic parse intentionally uses only the language/type
profile and is not semantic qualification of the omitted kernel options. No
diagnostic artifact is eligible for runtime export.

Native/GOTO comparisons isolated three concrete integration gaps:
`-ftrivial-auto-var-init=zero` does not initialize the GOTO local as GCC does;
`-fno-strict-overflow` permits a GCC wrapping addition that fails the stronger
model's signed-overflow obligation (native status is then UNKNOWN); and a conditional
expression combining a runtime zero-valued `void *` cast with an `int *`
received a different type in GOTO. The last difference affects the kernel's
constant-expression detection idiom and is corrected in the private frontend.
Further differential checks corrected `_Generic` pointer qualifier matching
and controlling-expression array decay, including qualified and typedef arrays.
The original kernel macros and source bodies are retained.

`build_semantics.py` now qualifies `-fno-strict-overflow`,
`-fno-delete-null-pointer-checks` and `-ftrivial-auto-var-init=zero` through
explicit contextual obligations. Native compilation retains these options.
Symbolic execution requires no arithmetic/pointer faults, no dependence on
implicit initialization and no observable implicit stores. If this stronger
model fails, raw properties remain available but native status/reachability
become UNKNOWN. These conditions are checked separately for baseline, action,
protected, all-PASS and actual-VM queries. They do not qualify all wrapping or
implicit-zero programs.

The build reader now records native code-generation options separately while
parsing argv, preserving their order and keeping include/macro operands out of
the native-option list. GNU dependency-output controls and macro prefix maps
are handled explicitly. The selected x86-64 code-model, ISA, stack and ordinary
optimization options are replayed into native objects; ABI probes use those
same options, require x86-64 LP64 for this machine profile, and reject mixed
stack calling conventions. This retains the native-compiler trust boundary;
it does not prove the generated machine code. 820 of the 861 captured kernel
recipes are admitted by the reader. 16-bit and freestanding boot profiles are
still rejected; reader admission is not a policy proof.

`-fno-strict-aliasing` and `-fno-allow-store-data-races` now join the contextual
profile. `-fstrict-flex-arrays=3` additionally requires that accesses or address
escapes of fixed trailing array members be unreachable. This current check is
conservative even for an in-bounds access; full subobject provenance remains
open. Ordinary nontrailing arrays are not rejected by that check. Compiler
queries (`__builtin_object_size`, `__builtin_dynamic_object_size`, and
`__builtin_constant_p`) have separate native-correspondence obligations because
the backend can fold them differently from GCC. Query-containing functions
must be unreachable. Discarded inline definitions qualify only when absent
from the linked compiler model and unreferenced by a conservative source graph
including global function-pointer initializers. Missing markers alone do not
establish unreachability.

`tests/platform_cases/kernel_integer_contract/prepare.py` now binds original
`lib/kstrtox.c` and `lib/ctype.c` using their full captured build recipes. A
kernel-header root covers all four-byte strings followed by a null terminator,
including shorter strings through interior nulls. The benign policy rejects
the `+` decimal prefix at `kstrtouint`. It preserves the caller's output sentinel
on errors and checks the successful decimal result range. Target, caller
contracts, initialization, conditional PASS and nonvacuity obligations have
passed. This is a declared caller context, not every kernel caller.

The runtime export's `--runtime-environment linux-kernel` mode uses the original
kernel include/macro environment for VM helpers, typed entry adapters and a
trap-based failure adapter. The real-VM query has passed for this original
kernel context, and native objects plus an archive have been compiled with the
recorded flags. The independent byte/dependency check reports
`CURRENT_FOR_GUEST_VALIDATION`. A callable exhaustive region self-test is
included as a kernel object, with status `PENDING_KERNEL_GUEST`. Neither that
object nor `BUILT_FOR_GUEST_VALIDATION` claims that it has executed in a kernel.
Kbuild integration, its objtool postprocessing, final image identity and the
policy-enabled isolated guest run are the next required steps.

## Verification scalability

The source locator preserves all bytes passed to the compilers while adapting
only its syntax view for canonical GCC line markers, balanced GNU attributes,
GNU type operands, anonymous aggregates, case ranges and asm string/inline
syntax. Malformed surrounding function statements are still rejected. The
original bytes go to both compilers; type and expression semantics are never
taken from this locator view.

String-literal initialization checks now share one compiler-typed, read-only
identity helper. Direct local/global scalar reads do not need literal alias
tests. This removes the previous copy of every literal comparison at every
read, which exhausted the 4 GiB validation environment on Nginx.

Compiler-generated declared C temporaries now receive shadow storage rather
than being skipped as auxiliary solver variables. A source correction to CBMC
6.11.0 keeps arrays of aggregates in the pointer-field shadow candidate set.
It changes neither application expressions nor read/write byte extents. The
official installed tools remain intact; a separate private CBMC executable and
its exact SHA-256 are bound into all new verification evidence.

Unsupported initialization effects and layout-sensitive operations now have
instruction-level unreachability obligations. The complete compiled program is
retained. A context qualifies only if every unsupported operation is proved
unreachable; reachable, missing and incomplete obligations remain UNKNOWN.
Lvalue qualifiers are recovered from compiler declarations when GOTO expression
types omit them. Volatile/atomic storage and the observed union-shadow limitation
are reported explicitly. Union initialization has not been qualified.

The patch is in `tools/backend_patches/`. `tools.build_shadow_backend` provides a
native Linux source-build recipe using pinned CBMC 6.11.0 and MiniSat archives,
a new private prefix and a separately retained backend manifest. The source
patch application and bad-archive rejection have been tested. The complete
builder CLI has also completed a second full source build, and its pinned
manifest passed a separate `CURRENT_BACKEND_BYTES` check. The two builds have
different executable fingerprints; the Nginx evidence remains bound to the
first, separately validated executable. The newly built executable separately
passed all 18 aggregate-pointer and compiler-temporary regression cases.
Upstream shadow-memory CORE tests passed on the original qualified executable (42 tests, with
one separately tagged upstream test skipped). This is backend qualification
evidence for the tested cases, not a universal soundness proof.

Every new source build also applies the pinned JSON control-character escaping
correction and rebuilds `cbmc`, `goto-cc`, `goto-instrument`, and `symtab2gb`.
This preserves C0 characters as JSON escapes in both string values and keys;
strict JSON decoding remains required. The builder checks the patch and original
and corrected `src/util/json.cpp` hashes, records the correction in its manifest,
and retains the patch, corrected source, patch log, and all four executable hashes.

The full typed-export build also applies a pinned streaming exporter patch.
Function code and guards retain recursive IREP annotations; every instruction
exports `sourceLocationIrep`, and every symbol exports `locationIrep`, including
raw nil locations. The CLI streams instructions while preserving the `convert`
API. The builder pins all seven changed source files before and after patching,
rechecks them after building, and records the patch, sources, log, and exporter
capabilities in its manifest. These capabilities describe the function wrapper
and outer symbol-table wrapper. The verifier's default full transport requires
the paired exporter and importer from this build, including the raw inspection
options below. Select that toolchain with `--toolchain`; an older official-only
installation needs the additional private backend build. Both model import
sites use an actual-model roundtrip gate that preserves raw and display locations.
The transport adapter moves raw locations into the importer's existing location
fields. The pinned importer correction preserves supplied SKIP code and complete
SET_RETURN_VALUE code, including outer annotations. Whole-model comparison still
checks the actual imported binary and rejects any unexplained information loss.

Full inspection uses `--show-goto-functions-raw` and `--show-symbol-table-raw` with
`--json-ui`. These modes return immediately after binary loading, before default
instrumentation, property relabeling or failed-symbol insertion. They require one
input and exactly one raw view and reject other operation options. Ordinary show
modes retain their prior instrumentation behavior. The build manifest records
these raw inspection options and the importer correction explicitly. A successful
source build alone does not establish application verification or cold-built tool
regression qualification.

Complete function exports are written to byte sidecars and parsed one function
at a time, with the enclosing JSON document and its final EOF checked. Command
records include sidecar lengths, hashes and exit status. Repeated checks in one
output directory continue command numbering after existing records and orphaned
stdout/stderr sidecars, preserving earlier command evidence. The explicit Python
legacy transport mode records incomplete preservation and retains UNKNOWN.

`--c-frontend` additionally applies the pinned integer-constant-expression,
generic-qualifier and generic-array-decay corrections. The earlier incremental
frontend build retains its upstream ANSI C results (242 passes, 19 profile/tag
skips) and shadow-memory results (42 passes, one tag skip) under its original
manifest. The previously delivered Nginx package likewise remains evidence for
its own frozen source/tool revisions.

On 2026-11-05, the integrated builder completed a fresh four-tool build from the
pinned CBMC 6.11.0 and MiniSat archives with `--c-frontend` and
`--pointer-difference-overflow`, one build job, and a 2560 MiB address-space cap.
Its manifest SHA-256 is
`9c5abe05dfde81420ec754dfaf36bd323f36af0adeb34eb6d35407dc582fd2e3`.
An independent `CURRENT_BACKEND_BYTES` check passed. Actual binary roundtrips
passed for unchanged models, explicit raw-location donors and complete return
annotations. All ten raw-view and opaque/nil/SKIP edge cases passed.

The cold-built binaries then passed 57 serial native regressions with no skips,
failures or errors. These cover changed-guard sufficiency and action-cache reuse,
callback branch/alias behavior, skipped caller-output writes, actual VM export
and execution, compiler-generated temporaries, aggregate-pointer and bit-field
initialization, and C type selection against GCC at `-O0` and `-O2`. The run
freezes production tools, tests and runtime sources, checks all manifest assets,
and rechecks source/tool bytes after execution. It does not inherit the earlier
build's upstream-suite results. Qualification records are in the task workspace
under `work/general-implementation/full-typed-cold-evidence-20261105-v1/`.
Toolchain selection remains explicit through `--toolchain`.

Both model import sites now also invoke `goto-instrument INPUT.goto
--validate-goto-binary --json-ui` immediately after a successful whole-model
roundtrip. This validation-only option checks the loaded types and GOTO
structure without writing the input. Reports retain the roundtrip result and
the separate `model_validation` result, then recheck the binary and transport
tool identities. A failed or timed-out validation, or a changed binary, rejects
the preparation even when serialization matched.

Initialization instrumentation now gives the shared string-literal helper its
own compiler-derived result temporary. Its C `_Bool` result cannot share the
integer temporary returned by `__CPROVER_get_field`: GOTO function-call results
require exact types and do not implicitly apply C assignment conversion. The
two temporaries retain their respective compiler types and source locations.
This corrects the type error found while validating the larger Nginx resource
model; the saved invalid model is retained and must be regenerated from source.

The integrated revision passed 139 serial tests against the cold-built backend,
with no failures, errors or skips. The added native tests cover both initialized
and uninitialized reads through a pointer that may select a string literal;
transport tests cover validation failure, timeout and changed output bytes.
Three additional actual model roundtrips passed after integration with native
validation enabled. These checks qualify model construction in their tested
scope; application proof results still require fresh queries on the corrected
models. Integration hashes and original files are retained in the task workspace
under `work/general-implementation/literal-return-integration-20261105-v1/`.
