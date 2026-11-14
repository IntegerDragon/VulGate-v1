# Candidate pointer-difference overflow correction

The optional `--pointer-difference-overflow` build flag adds a pinned CBMC
6.11.0 correction for pointer-pointer subtraction checks. It is disabled by
default and remains a candidate backend correction. A successful build or
manifest check establishes artifact identity; semantic qualification and
application verification require their own recorded results.

The patch is
`tools/backend_patches/cbmc-6.11.0-pointer-difference-overflow.patch`, with
SHA-256:

```text
f86b41bdd2981cb1448f625fb5805d84c5c7cff2b815d37556d1c46f85886c54
```

The original integer overflow path applied arithmetic to pointer encodings.
The correction checks the range of the element distance: it extracts both
pointer offsets, subtracts in a sufficiently wide signed type, divides by
the positive static element size, and compares the result with the result
type's bounds. Existing same-object and pointer-validity checks remain
separate. Ordinary integer overflow checks retain their implementation and
option gates. An unsupported pointee type or size produces an explicit
tool error, which must be handled as UNKNOWN rather than a program violation.

The protected offset expressions retain their normal backend operation and
carry a private preservation marker through GOTO serialization. The solver
uses its runtime pointer layout, including `--object-bits`; instrumentation
does not bake an earlier offset width into the range predicate. The build
flag selects the source correction. It does not enable verification checks
that were otherwise disabled in the instrumentation or verification command.

## Build in a fresh private prefix

Run the existing native Linux builder with the pinned source and MiniSat
archives and a native base-toolchain configuration:

```sh
python -m tools.build_shadow_backend \
  --prefix /path/to/new-pointer-difference-backend \
  --cbmc-archive /path/to/cbmc-6.11.0.tar.gz \
  --minisat-archive /path/to/minisat2_2.2.1.orig.tar.gz \
  --base-toolchain /path/to/native-toolchain.json \
  --pointer-difference-overflow
```

Add `--c-frontend` when the existing C frontend corrections are also wanted.
The two options are independent. Either option builds and installs all four
tools from the private source tree: `cbmc`, `goto-cc`, `goto-instrument`, and
`symtab2gb`. The default without either option retains the existing shadow
backend build behavior.

The builder applies the existing shadow patch, the optional frontend patch
sequence, then the optional pointer-difference patch. These corrections
change disjoint files. The pointer-offset-cache and experimental SSA
simplification patches are not implicitly included.

The builder pins the correction patch before creating the output prefix,
checks the three existing source files and absence of the new header before
patching, and checks all four resulting files both after patch application
and after compilation. Its manifest records the option, patch, header,
sources, logs, commands, and executable fingerprints. The normal
`--check-sha256` mode validates those recorded assets. Historical manifests
remain bound to the builder revision that created them.

## Regenerate previously checked GOTO inputs

A previously generated `checked.goto` can already contain the old pointer
subtraction overflow assertion. Running only a new `cbmc` executable on
that file does not replace the embedded assertion. Running instrumentation
again on an already checked file can also retain the old property alongside
new ones.

Inspect the recorded tool commands and actual GOTO assertion inventory
first. A filename containing `checked` does not establish that standard
overflow checks have been embedded. The frozen Nginx resource input, for
example, was imported by `symtab2gb` with initialization and callback-target
markers; its standard overflow checks are added by the subsequent CBMC
invocation. An audit of that input found 4,157 preserved assertions and no
embedded overflow predicates. That same input can be retained when the new
CBMC generates the checks, preserving the callback-target markers.

If the old overflow assertions are embedded, start from the corresponding
input before that check instrumentation, or regenerate it from source, and
perform the original instrumentation step with the corrected tools and
original check options. Save a new artifact and retain the old evidence.
For newly generated pipelines, use the new four-tool configuration
consistently and record executable and GOTO hashes. Do not manually delete
a failing assertion to adapt an old input.

## Qualification boundary

The 2026-11-04 private candidate rebuilt three affected translation units
and libraries and relinked all four tools. Its CBMC SHA-256 is
`e4a909d6324c7a7a196f85858f7bf1cb4794fe82201eb00dd2d873a7e82b78b4`.
Recorded checks for those binaries and the integrated source are:

- 35 ordinary C programs at 32 and 64 bits, compared with the original
  backend: 140 executions, 70 expected comparisons, including 12 repaired
  legal pointer-distance properties. Integer-overflow and invalid-pointer
  negative tests retain their required failures. Fatal NULL checks retain
  ten subsequent UNKNOWN properties per run; those are not successes.
- 41 scenarios invoking the actual predicate builder at integer range
  boundaries and different element sizes, plus unsupported-type and marker
  checks. Artificial pointer widths make narrow result boundaries
  reachable; this is a predicate test, separate from pointer encoding.
- GOTO compile/instrument/save/read checks at 32 and 64 bits, with the same
  saved GOTO verified at object-bit settings 8 and 13: eight executions.
- 205 distinct repository tests passing, including real official-source
  patch application and patch combinations, preflight rejection, target
  selection, frontend semantics, and verification integration. The first
  report had 196 passes and nine frontend skips; the nine were then run
  explicitly and passed.

The private build used the recorded incremental builder against existing
pinned archives. The repository builder's patching and command selection
were tested; a fresh full CMake build through this optional CLI has not
been run in this stage. The experimental SSA optimizations were not part
of these candidate binaries.

Application conclusions must refer to newly generated checked GOTO and
its own backend hashes. The Nginx resource task still has an UNKNOWN
overall result on its earlier frozen backend. These correction regressions
do not complete that application proof or the Linux-kernel resource work.
