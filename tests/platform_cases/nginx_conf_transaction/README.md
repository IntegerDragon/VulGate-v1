# Nginx configuration-file transaction input

This input runs the original Nginx 1.28.0 `ngx_conf_parse`,
`ngx_conf_read_token`, `ngx_alloc` and `ngx_read_file` from a separately
configured non-debug source tree. The setup script compares the prior
configuration, removes `--with-debug`, selects an independent prefix, and
captures a fresh complete build with `tools.build_capture`. Original source,
configured trees, captures and earlier evidence remain separate.

The ordinary policy rejects nonempty configuration files by returning
`NGX_ERROR` at the `ngx_conf_read_token` entry when
`cf->conf_file->file.info.st_size > 0`. The caller has already acquired the
descriptor, initialized metadata and allocated its input buffer. Its original
cleanup path must free the buffer, attempt the close once and restore the
previous `cf.conf_file`. Empty configuration is a PASS case. The input is one
transaction, with 0--2 bytes drawn from space, tab, CR, LF and `}`. Whitespace
supplies baseline acceptance cases; `}` supplies an ordinary syntax-error path.

`environment.c` supplies explicit C implementations of `open`, `fstat`,
`pread`, `close` and thread-local errno access for this single-threaded root.
The file is immutable during the transaction; there are no concurrent users,
signals that mutate program state, descriptor reuse, symlinks or other files.
`open` either acquires one read-only descriptor or fails with `EACCES`.
Successful `fstat` initializes its entire output and reports the input length.
`pread` can return the requested bytes, a short read, or `EIO`; only returned
bytes are written. Allocation and deallocation use the standard malloc/free
model, with allocation failure retained and `memory_cleanup` enabled.

For a valid descriptor, this Linux close model records release before an
optional `EIO` or `EINTR` report. `close_attempts`, `released` and
`close_failures` are separate fields. The invalid-descriptor `EBADF` branch
does not release anything and is subject to a live-descriptor assertion. This
is a Linux-specific environment premise; it is not a POSIX-wide claim that
all close failures release a descriptor. Descriptor retry/reuse and concurrent
close are outside this input.

The `root` task supplies successful `fstat` for any acquired file while
retaining open/read/close/allocation failure paths. The separate
`root_fstat_failure` diagnostic forces successful open and failed `fstat`,
which leaves its output untouched. Original Nginx logs that failure and
continues; the subsequent `file.info` initialization premise has not been
established. This task preserves the source and the missing premise for
diagnosis. It does not assume a successful allocation or initialize the
failed output on the caller's behalf.

The two variadic logging functions use explicit `task.environment` summaries.
Their body fragments discard named parameters and have no memory, resource,
allocation, errno or variadic-read effects. Caller argument evaluation remains
part of the program. This projects logging out of the file-transaction state;
formatting, output, log callbacks and log-resource effects require their own
qualification. The original functions remain in the native Nginx build.

The root asserts result-domain membership, restoration of the original
configuration pointer, acquisition/metadata/close counts, descriptor release,
bounded reads and error propagation. Buffer cleanup remains checked through
the original memory properties, with no malloc/free replacement. The
configuration dump switch is zero and `NGX_DEBUG` is absent, so the real
configuration-dump branch is disabled by the selected build and root input.

Preparation uses the workspace script `setup_nginx_resource_task.py` with
separate `build` and `prepare` phases. The generated `task.json`,
`task.fstat-failure.json`, `policies.json` and `policies.pass.json` are inputs;
preparation and native compilation do not establish verification results.

The captured optimized build also uses glibc fortified `open/open64` and
`pread/pread64` definitions. The initial C input definitions alone do not bind
those inline wrappers: an initial fixed-input query exposed missing vararg
builtins and recursive alias resolution. The workspace runner
`prepare_nginx_posix_boundaries.py --source-task TASK --output NEW_DIRECTORY
--include-pread` prepares explicit summaries for the definitions actually
present in each preprocessed translation unit. They forward to
`vg_open_contract` and `vg_pread_contract`, renamed versions of the C models
above. Their resource assertions and buffer writes remain executed obligations.
The wrappers retain their original signatures and caller argument evaluation;
their libc API behavior becomes a recorded environment premise. The generated
task records each original body, signature and source identity. Use this
boundary-qualified input for subsequent queries, with the scope from its
actual root harness; a fixed-content partition covers only that partition.
