# Linux kernel image binding

`python -m tools.kernel_binding` binds a pinned kernel runtime export to a new
Kbuild image. Run it on the Linux build host. Inputs are the verified task and
policies, runtime manifest and caller-retained hash, original source tree,
baseline build directory, and selected original kernel translation units.

```sh
python -m tools.kernel_binding build \
  --task task.json --policies policies.json --toolchain toolchain.json \
  --runtime /path/to/runtime/manifest.json --runtime-sha256 SHA256 \
  --source-tree /path/to/linux --baseline /path/to/baseline-build \
  --source /path/to/linux/lib/example.c \
  --probe /path/to/guest_probe.c --output /path/to/new-image-bundle --jobs 4
```

The probe is optional. When supplied, it defines
`int vulgate_kernel_policy_probe(void)` and returns zero on success. The binder
adds a late initcall which first invokes the runtime's exhaustive decision-region
self-test, then the supplied probe. The generated boot check prints the runtime
manifest identity. The fixture in `tests/platform_cases/kernel_integer_contract/`
uses ordinary decimal strings and the original `kstrtouint` API.

The build directory must be new and disjoint from the baseline, source tree and
runtime bundle. The baseline is copied without hard links. The compiler
interposer compares the selected unit's complete admitted preprocessing and
native options and its preprocessed bytes with the runtime proof. It preserves
the original compiler invocation name and ordinary dependency generation,
then substitutes the pinned object before Kbuild runs its remaining rule.

Runtime helpers and boot checks remain separate objects. Each receives the
recorded objtool pass, and the original Kbuild archive inputs are extended with
those objects. Kbuild performs dependency processing, selected-object objtool,
archive construction, modpost, vmlinux linking and bzImage generation. The binder
checks archive membership, runtime symbols, configuration identity, input
freshness, and implementation identity. Objtool diagnostics prevent successful
binding. The bundle records both raw and postprocessed object identities.

The current profile uses x86-64 GNU GCC/binutils, non-LTO Kbuild, per-object
objtool, and the recognized `ar cDPrST vmlinux.a` construction. MODVERSIONS,
Clang CFI, livepatch, function tracing and GCC randstruct are not admitted.
Other build recipes need their own correspondence and provenance qualification.

Successful binding reports `LINKED_FOR_GUEST_VALIDATION`; it does not execute
the image. To check the recorded bytes independently:

```sh
python -m tools.kernel_binding check \
  --manifest /path/to/new-image-bundle/manifest.json --sha256 IMAGE_MANIFEST_SHA256
```

`CURRENT_LINKED_BYTES` confirms the recorded image, object/archive/command
assets, runtime assets, baseline identities, implementation and native tools.
The build also checks the runtime proof against current source and compiler
context before and after Kbuild. An image-byte check does not rerun symbolic
verification or attest a running kernel.

Use the diskless QEMU runner for execution evidence:

```sh
python tests/platform_cases/kernel_guest/run.py \
  --build /path/to/new-image-bundle/build \
  --binding /path/to/new-image-bundle/manifest.json \
  --binding-sha256 IMAGE_MANIFEST_SHA256 --output /path/to/new-guest-evidence
```

The runner uses TCG, one virtual CPU, 256 MiB RAM and no network or disks. It
checks the image binding before and after boot. A policy-enabled run requires
exactly one successful VM marker, the expected runtime identity, and the probe
success marker when a probe was supplied, in addition to normal boot, procfs,
sysfs and reboot. Missing, duplicated or failed policy markers cannot pass.
The original runtime export retains its historical `PENDING_KERNEL_GUEST`
field; the separate guest report supplies the later execution evidence.

The verified root and its input bounds remain the proof scope. The kernel
fixture uses base 10 and a NUL-terminated buffer with at most four arbitrary
bytes, checks preservation of the output sentinel on negative returns, and
requires leading `+` to be rejected. A full linked image and a successful guest
probe do not enlarge that scope to every kernel caller or execution history.

`tests/test_kernel_binding.py` checks actual GCC object substitution and
dependency generation, configuration/source/object drift, thin-archive member
paths, helper selection, image tampering, and guest marker requirements.
