# ENGINE83 exact backup transport

The original combined lock remains unchanged: ENGINE83 run `36069973563`,
attempt `1`, producer `4f0d60f6b83244fbcc0ef268b0914cb7cd820354`. Its Actions
checkpoint and summary artifacts expired after the former seven-day retention.
The local copy was uploaded again without decrypting or regenerating either ZIP.

The reviewed backup carrier is run `36975195624`, attempt `1`, commit
`49f5d947f1c40f98e75369ee0b66ec1aa6fdc5e7`, workflow
`local-checkpoint-reupload.yml`, branch `temporary/checkpoint-reupload-20261002`.
Artifact `11213402934` is named
`cef-strict-checkpoint-backup-linux-36069973563-1-36975195624` and contains exactly
`checkpoint.zip`, `summary.zip`, and `transport-receipt.json`.

Transport byte length: `16753710075`.
Transport SHA-256:
`9b1fbbcc022ec1b70b738b333674533ace3c3368cf60a168d3b61ec4d1a28bc9`.
Original checkpoint ZIP SHA-256:
`90950cf0792a7f644ba5e40c73edc1793cf2f8cc6483bac306d3af566dbd8df3`.
Original summary ZIP SHA-256:
`fc003422a66b6997f3e78c8953a03cfcb85aefd1e18e6bca4f0d50eabfdaadb3`.

`secure_release.cef_checkpoint_backup` enables this carrier only for the exact
nine-field original selector. It checks both the current and historical attempt
of the original producer and the carrier, their repository IDs, revisions,
workflow/event/branch and successful conclusions. Carrier metadata must match
its exact ID, name, size and digest, and retain at least the existing six-hour
job window. The cheap gate reads metadata only, not 16GB of ciphertext.

The production worker downloads the carrier into a new process-owned directory,
hashes the entire ZIP, checks its three bounded regular members, and streams
both nested ZIPs through their ORIGINAL SHA-256 checks before supplying even
the summary to the original validators. ZIP64 is supported; no member path is
joined except the three fixed basenames. The receipt is checked but cannot
supply an alternative hash, URL, producer identity, or qualification claim.
The carrier is fetched once per process and removed after verified extraction;
original ZIPs are rehashed when copied and the private process cache is removed
when restore takes ownership. No existing disk cache or concurrent output is
silently adopted or overwritten.

All existing summary qualification checks, original producer post-restore
checks, checkpoint envelope/context authentication and payload/host/driver
checks remain mandatory. The authenticated context uses original ENGINE83
run/attempt/revision, NEVER the carrier's IDs. Unknown selectors retain the old
fail-closed path; missing or changed transport never falls back to a fresh engine.
No keys, permissions, encrypted formats, lock files or SDK acceptance criteria
change. The temporary re-upload workflow and release are not copied into the
qualification branch.

Carrier upload success and tests with disposable keys are not final SDK
qualification. The next Strict run must verify the actual original ZIPs and
checkpoint, restore the 131909 outputs, and then complete installed/exported/
relocated CEF and canonical lfc-ui[freerdp,cef] runtime, module, listener and
hidden-root proofs. Public summaries distinguish backup transport IDs and
verified original ZIP hashes from the unchanged original producer and runtime
result. Keep an independent saved copy; 90-day Actions retention is not a backup.
