# Strict CEF runtime progress diagnostics

Run 35859298080 (#70, builder e233b9ee529647386493dd861e4e4287b6504a55)
completed compilation and the final static-GTK link. Its summary records
131901 outputs, 2293 changed outputs, successful NSS and JPEG/TIFF namespace
checks, and a reusable checkpoint. Its reference smoke timed out; this is NOT
engine runtime or SDK qualification.

The diagnostic logs contain no new GTK registry or linker failure signature.
That absence does not prove that the GTK feature set, module closure, JavaScript,
paint, IPC or shutdown is correct. Existing timeout process metadata does not
identify the unsatisfied smoke predicate. Do not guess from routine D-Bus
startup warnings, relax the module allowlist, disable GTK, extend the timeout,
or mark the SDK ready to bypass this uncertainty.

## Proven reference-test defect

The pinned C fixture silently returned from `finish` when a renderer explicitly
reported a failed module audit or an invalid/same-process PID. No subsequent
event could turn that negative proof into a valid one, yet the test waited for
the external watchdog. Fail immediately by closing the test browser, without
setting `passed`. An absent renderer proof remains a wait, not a rejection and
not a success. The successful JS, exact pixel, separate-process, module and
receipt checks are unchanged.

## Scoped instrumentation

The workflow calls `cef_strict_iteration_runtime`, which delegates to the
unchanged worker. Its scoped adapter instruments only the reference C fixture
after successful pinned source/GN preparation and before the compilation slice.
It restores its Python hooks and environment on all exit paths. Checkpoint,
recipe, crypto and qualification gates remain owned by the original worker.

The complete original smoke file is bound to Git blob
`2b152219424a2ca9f944bf231577a5ae1d7f8999`. Every transformation anchor must match
exactly once. The installed file, header and policy are digest-bound, and repeat
installation preserves clocks. The recipe checkout and base patch marker are
not changed. The existing exporter excludes the reference smoke object from the
SDK; this instrumentation does not become an SDK feature.

Per-process atomic snapshots report fixed numeric state only: initialization,
browser creation, renderer context, proof transmission/reception, title/JS,
paint count and the fixed test pixel, module audit results, close and shutdown.
Optional bounded module inventories contain sanitized basenames only. No
arguments, environment values, URLs, images, dumps or arbitrary log messages are
recorded. Snapshots live under the runner-local engine log directory and are
collected by the existing encrypted-diagnostics action. The public summary gets
only allowlisted scalar state, fixed stage names and unexpected-module counts.
These diagnostics can explain a failure but can never grant qualification.

Native C regression tests reproduce the old silent return and require the new
negative-proof cases to close unsuccessfully; positive and incomplete-proof
cases retain their original outcome. This is a fixture regression, not a full
CEF runtime test. A separate workflow preflight checks the complete pinned CEF
source before restoring the expensive engine checkpoint.

The engine selector advances to the authenticated #70 checkpoint. The combined
selector remains null until the GTK-enabled engine is actually runtime-verified.
