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
