# Strict CEF checkpoint availability and retention

A green source/test commit cannot replace a missing engine checkpoint. Both the
non-sensitive producer summary ZIP and encrypted checkpoint ZIP selected in
`ci/cef-strict-combined-lock.json` are required. Availability is not qualification:
the existing worker still authenticates the producer, summary bytes, all encrypted
parts, build key, complete workspace identity and runtime proofs before reuse.

## Prevent expensive work on an unavailable checkpoint

`secure_release.cef_checkpoint_availability` performs read-only metadata requests
using the existing Actions read permission and short-lived `github.token`.
Combined runs check the exact producer and both artifact IDs, names, SHA-256
metadata, expiry and a six-hour remaining lifetime in the cheap gate, before
private checkouts or native prerequisites. Six hours covers the existing
350-minute Linux job budget. Engine iterations perform the same check immediately
after the builder checkout; explicitly unselected fresh-engine mode is preserved,
but an unavailable selected checkpoint never falls back to it.

The probe does not download/decrypt checkpoint bytes, authorize an alternative
producer, edit a lock, renew retention or reserve availability. The restore worker
must still repeat all existing provenance, digest and cryptographic checks. A
race/deletion after the probe remains a fatal restore failure.

## Retention is not a backup

Future engine checkpoint and summary uploads request **90 days**, the maximum
for public repositories, instead of the former seven-day setting. Repository or
organization caps must also allow that period. GitHub applies retention changes
to new objects only; this change cannot recover already expired/deleted objects.
Keep an independently retained copy of the original ciphertext ZIP and summary
ZIP before expiration. Keep keys and decrypted workspaces out of repository files,
issues and Actions artifacts. Never rerun an old producer to pretend to extend
its original attempt: the current restore contract explicitly rejects that.

## Incident: ENGINE83 required by combined #140

Combined run `36964218760` failed at `checkpoint-host-identity` before restore,
not in CREL/COMDAT conversion or CEF runtime. On 2026-10-02 both original IDs
returned HTTP 404; the producer's artifact list contained only diagnostic logs.
The engine upload workflow retained checkpoint and summary for seven days.
Changing retention now or rerunning combined cannot recover the missing bytes.

Original immutable selector (left unchanged):

| Item | Original identity |
| --- | --- |
| Producer | `dobord/builder`, run `36069973563`, attempt `1` |
| Producer commit | `4f0d60f6b83244fbcc0ef268b0914cb7cd820354` |
| Encrypted checkpoint artifact | `10839464034` |
| Checkpoint ZIP SHA-256 | `90950cf0792a7f644ba5e40c73edc1793cf2f8cc6483bac306d3af566dbd8df3` |
| Producer summary artifact | `10839723709` |
| Summary ZIP SHA-256 | `fc003422a66b6997f3e78c8953a03cfcb85aefd1e18e6bca4f0d50eabfdaadb3` |

Recovery requires an exact saved copy of those archives, or investigation of an
actually preserved original workspace. A relocated SDK or diagnostic-log archive
is not the 131909-output engine checkpoint. Merely substituting another artifact
ID or summary, or starting a fresh engine, is not an authorized recovery. If exact
bytes are available at a new location, review a narrowly scoped immutable transport
binding that retains the original hashes, producer identity, encrypted context and
all original validation. Until then, qualification remains blocked; do not schedule
repeated expensive reruns or claim that the final SDK is qualified.

Official retention documentation:
https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository
