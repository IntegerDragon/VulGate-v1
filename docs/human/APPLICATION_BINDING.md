# Application link and installed-file binding

`python -m tools.application_binding` links selected native objects from a
caller-pinned runtime export and records the resulting executable. The same
entry point checks a build executable or an installed copy against a separately
retained application-manifest SHA-256. All program-specific selection lives in
task and policy inputs, not in this implementation.

The initial supported profile is GCC, GNU ld/readelf, Linux x86-64 ELF, through
the native Linux backend or Windows/WSL. Windows/WSL is the exercised profile.
The host supplies Python 3.11+ for reading execution-host link inputs. All
application translation units must use one recorded compiler and compatible
ABI. PIE and non-PIE executable link modes are accepted. Captured builds can
retain ordinary `-l`/`-L` library arguments, `-pthread`, and symbol-export flags.
Arbitrary link flags, custom scripts, compiler/linker plugins, LTO, and
environment search-path/interposition overrides require further qualification.

## Build

First include the native entry point in the ordinary verification task and
export the runtime artifact. A separate symbolic root may remain the verification
entry. For the benign integration case:

```sh
python -m tools.verification \
  tests/verification_cases/runtime_contract/application-task.json \
  --policies tests/verification_cases/runtime_contract/policies.json \
  --export-runtime --toolchain toolchain.json --output runtime-output
```

Retain the `manifest_sha256` returned by that operation outside the bundle.
Then use its manifest path and saved hash:

```sh
python -m tools.application_binding \
  tests/verification_cases/runtime_contract/application-task.json \
  --policies tests/verification_cases/runtime_contract/policies.json \
  --toolchain toolchain.json --runtime RUNTIME_MANIFEST \
  --sha256 SAVED_RUNTIME_MANIFEST_SHA256 \
  --source tests/verification_cases/runtime_contract/program.c \
  --source tests/verification_cases/runtime_contract/native.c \
  --application-id record-service --version 1.0 \
  --output application-output
```

`--source` is repeatable and resolves relative to the current directory. Every
selected source must have been part of the runtime task. Every policy-bearing
translation unit must be selected. The symbolic harness object can be omitted;
the VM, generated bridge, and failure adapter are always included. No new C
source is compiled at this stage. The selected objects are linked explicitly,
so archive member extraction cannot silently omit a selected policy unit.

The runtime export supplies the native implementation of verification
assertions: it returns for a true condition and calls `abort` for a false one.
The symbolic query retains CBMC's intrinsic assertions and original labels.
Application sources must not redefine that intrinsic. This lets a native
`main` enter the analyzed source set without introducing a conflicting
definition of CBMC's internal Boolean type.

The builder checks the upstream manifest and current source/build/toolchain
dependencies before and after linking. It runs a preliminary link, inventories
the trace, and runs a final link with the same arguments. The trace must agree
and contain every selected object. All traced inputs, including CRT objects,
runtime archives, library linker scripts, libc and the ELF loader, are recorded
by path spelling, resolved path, size, and SHA-256. GCC, collect2, ld, readelf,
GCC specs and the default GNU linker script are also bound and rechecked.

The application manifest records the executable's SHA-256, ELF metadata,
version label, source-to-object mapping, runtime-manifest pin, link map, link
trace, and the binding implementation's hash. `LINKED_WITH_HARNESS_EVIDENCE`
means the link and its evidence were bound successfully. It does not extend
the verification root to every possible call from native `main`.

## Bind a complete captured application

On the original Linux build host, add `--capture CAPTURE/manifest.json`,
`--capture-sha256 SAVED_CAPTURE_PIN`, and `--captured-output ORIGINAL_EXECUTABLE`
to the build command. The original executable selects exactly one completed
link invocation. Selected runtime sources must have been preprocessed from
that exact captured compilation database and recipe.

The linker replaces those original object paths with the pinned runtime
objects, adds the VM helpers, and preserves the remaining object/library
order. It writes a new executable inside the output bundle. It checks the
captured source/object/compiler identities before and after linking and binds
all actual library/CRT inputs from the final link trace. Captured response files
are expanded literally and fingerprinted; unsupported linker options fail.
An application check also rechecks its original capture manifest and object
mapping. The original build remains a dependency of that freshness check.

Capture records do not attest historical header bytes. The unchanged native
objects and the selected current verification snapshots are independently
pinned; the declared caller harness remains the scope of the proof. This link
evidence does not establish all native callers' contracts or runtime shared
library resolution on a different installation.

## Check a build or installed file

Retain the returned application-manifest hash independently of its bundle.

```sh
python -m tools.application_binding \
  tests/verification_cases/runtime_contract/application-task.json \
  --policies tests/verification_cases/runtime_contract/policies.json \
  --toolchain toolchain.json --check APPLICATION_MANIFEST \
  --sha256 SAVED_APPLICATION_MANIFEST_SHA256 \
  --installed /path/to/copied/application --output installation-check
```

For Windows/WSL, `--installed` is a Windows path accessible on the mounted
drive. Omit it to check the build executable. The check revalidates the upstream
runtime, link inputs/tools, and supporting link evidence. It hashes the selected
file itself against the manifest. An installed copy can pass when the original
build executable is missing. A changed build copy cannot redefine the accepted
installed bytes. A version is an externally supplied release label bound to
those bytes; the checker does not infer an application's self-reported version.

Successful byte checks return `CURRENT_LINKED_BYTES` or
`CURRENT_INSTALLED_BYTES`. Invalid or stale evidence returns `STALE_OR_INVALID`;
invalid CLI arguments or an invalid external manifest pin also return exit 2.
Exit 0 reports the requested binding/check operation succeeded. The overall
verification field remains `UNKNOWN`, and `deployment_ready` remains false,
because root coverage, lifecycle/environment assumptions and compiler trust
are separate obligations. Checks do not execute or install the application.

The manifests describe on-disk artifacts at the time of checking. They do not
attest a running process, its dynamic-loader environment, OS configuration,
external state, or arbitrary future changes. The build trusts the compiler and
platform tools; it does not prove machine-code equivalence. Before/after hashes
detect persistent changes across the checked stages, not a hostile filesystem
that substitutes and restores bytes between observations. Broader race-resistant
snapshots and process binding remain separate work.

## Validation

`tests/test_application_binding.py` covers compiler line markers inside expanded
expressions, exact object selection, path boundaries and external pins, real
GCC/VM application execution, independent installed-byte checks, changed output
and selected objects, and execution-host file/symlink identities.

Set `VULGATE_TOOLCHAIN` to run the real integration tests. Optionally set
`VULGATE_APPLICATION_RUNTIME_REPORT` to reuse a completed export for the exact
integration task; the builder still performs all freshness checks. No validation
status should be inferred from this description alone; see the corresponding
JUnit and command-evidence records for executed results.
