# Typed C entry adapters and the existing VM

This task combines two entry policies across two translation units. `apply`
reads a nullable pointer to a structure, observes signed and unsigned fields,
and has two distinct integer refusal returns. `mark_pending` has a void return;
its caller initializes the output before a possible refusal.

```sh
python -m tools.verification tests/verification_cases/runtime_contract/task.json \
  --policies tests/verification_cases/runtime_contract/policies.json \
  --export-runtime --output build/verification/runtime
```

Add `--toolchain /path/to/toolchain.json` when using a configured CBMC toolchain.
The export first verifies the supplied policies, then checks the actual native
adapter and VM sources in the original caller context. C evaluates the typed
observations; the existing DSL compiler produces VM monitors over the resulting
region number. The VM does not reinterpret the application's raw arguments.

The generated `libvulgate_verified.a` contains objects for the task sources and
the VM adapter. Link the included `native.c` with that archive using the recorded
compiler and matching ABI flags. The separate verification harness object is
not selected by the linker because the native driver does not reference it.
The native driver checks ordinary passing and refusal cases, signed values,
integer boundaries, pointer short-circuiting, multiple actions, and void return.

The export report records `manifest` and `manifest_sha256`. Check these against
current inputs before consuming the archive:

```sh
python -m tools.verification tests/verification_cases/runtime_contract/task.json \
  --policies tests/verification_cases/runtime_contract/policies.json \
  --check-runtime PATH_TO_MANIFEST --runtime-sha256 EXPECTED_SHA256 \
  --output build/verification/runtime-check
```

`BUILT_FOR_HARNESS` means the archive was built and its declared caller context
was checked. `CURRENT_FOR_HARNESS` additionally checks artifact integrity and
current source/build/tool identities against the caller-pinned manifest. The
pin must come from the accepted export, not be recomputed from a possibly
modified manifest during checking. These statuses do not certify a different
linked application or an installation; overall status remains UNKNOWN, exit
code 2, and deployment readiness remains false.
