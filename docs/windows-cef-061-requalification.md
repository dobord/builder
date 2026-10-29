# Fresh Windows CEF qualification for SDK 0.6.1

The release attempt on hosted Windows image `20261022.344.1` correctly rejected
the existing qualified checkpoint because its critical host fingerprint changed.
Do not relabel that checkpoint, relax fingerprint equality, or promote its old
runtime receipt as evidence for the new host.

The operator approved fresh qualification on the current Windows runner. Set the
iteration lock's checkpoint to `null`, preserving exact CEF/Chromium/V8/PDFium
source pins, static source-repair profile, encrypted transport and runtime gates.
The existing release lock remains untouched and closed to the new host.

Only explicitly accepted, successful iteration checkpoints may advance the
resumable iteration lock. Engine compilation completion and browser/renderer
runtime verification are both required before admitting a new release checkpoint.
Then bind its exact producer, attempt, artifact/summary digests and build key in
the reviewed release policy and signed SDK plans; run both final SDK consumers
and independent publisher verification again. Compatible dependency package
caches may be reused under their original authenticated contexts and ABI checks.

## Qualified current-host checkpoint

Run `40902424067`, attempt 1, producer
`98c52629af8c92e7655cbe2c2f2b6b874da97da4` completed engine compilation and
native browser/renderer runtime verification on image `20261022.344.1`.
The authenticated summary has `ready`, `checkpoint_ready`, `runtime_verified`,
`source_repair_verified` and `checkpoint_host_verified` all true. Compilation
completed with 132475 outputs. Exact artifact and summary digests are bound in
`ci/cef-windows-release-lock.json`; previous producer attempts remain unchanged.
This qualifies the engine checkpoint only. New final SDK consumers and the
independent publisher must still succeed before SDK 0.6.1 publication.
