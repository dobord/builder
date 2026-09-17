# CEF acquisition and encrypted build continuation

## Implemented contract

A signed release plan with `version: 2` has the original version-1 fields plus
`cef`. Each platform must explicitly request the `cef-static` root package.
Version 1 remains compatible for existing plans without CEF. A CEF package or
receipt without its signed acquisition contract is refused by the publisher.

The `cef` object has exactly these fields:

```json
{
  "schema": 1,
  "recipe_commit": "FULL_40_HEX_REVIEWED_CEF_INTEGRATION_COMMIT",
  "profile": "engine-static",
  "release_lock": null,
  "platforms": {
    "linux": {"mode": "source-fresh", "checkpoint": null, "binary_cache": null},
    "windows": {"mode": "source-fresh", "checkpoint": null, "binary_cache": null}
  },
  "slice_seconds": 9000,
  "jobs": 4
}
```

The placeholder must be replaced with a real reviewed SHA. `release-import`
requires the exact release lock from that recipe; `source-resume` requires an
explicit checkpoint selector. Modes may differ across platforms. No missing
checkpoint can silently become a release import, older checkpoint or cold build.

A selector has `run`, `attempt`, `artifact_id` (positive integers) and
`artifact_sha256` (64 lowercase hex characters). Values are recorded in the
PRIVATE signed plan, not supplied through an untrusted public workflow output.
A changed source workspace commit can select an old compatible CEF checkpoint;
its run ID and operational budget do not become part of the CEF package ABI.

## Execution and caching

The builder materializes `ports/cef-static/cef-build.json` before ABI calculation.
The file records the recipe, native triplet, acquisition mode, profile and release
hashes. Fresh/resume normalize to the same source identity. Source work lives at
`RUNNER_TEMP/encrypted-release-private/cef-work`, outside vcpkg's buildtrees.
It uses the original reviewed CEF GN/Ninja recipe and checkpoint codecs.

A clean unfinished slice saves a checkpoint and returns no installed package.
The SDK upload requires `sdk_ready=true`. The independent completion handler
requires BOTH platform SDK artifacts, so a green checkpoint-only run never
triggers publication. Compilation errors, stalled progress and incompatible
checkpoints remain errors. A checkpoint can preserve partial compiler progress
but never serves as a runtime certificate.

Completed vcpkg packages use a job-local `files` binary provider after inherited
providers are cleared. The full local cache is encrypted before upload. Source
checkpoints and vcpkg binary caches are separate artifact kinds. Every cache
requires the exact approved builder revision, producer run/attempt, workflow,
repository identity and GitHub artifact digest. Restore is staged, validates all
members, rechecks producer stability and refuses to overwrite existing state.

Cache transport contains only `index.enc` and numbered `.enc` parts. Filenames,
content hashes and platform graph details stay inside the encrypted index.
The existing builder INPUT HPKE recipient is used with domain-separated cache
contexts; the SDK OUTPUT decryption private key remains private-publisher-only.
This deliberately makes input-key rotation invalidate old cache access. The
compiled recipe receives no cache key or API credential. Cache metadata does not
authorize a release; each new request is still signed and expires after 48 hours.

Checkpoint parts retain the source codec's integer timestamps, generated inputs
and internal-link policy. SDK validators are NOT relaxed to permit Git metadata
or source workspace links. A source checkpoint from another repository, path,
runner image or recipe is rejected; cross-repository/image migration has not been
implemented and must not be emulated by editing its identity JSON.

## Consumer and publication gates

Both import and source modes end in a new combined consumer from the exported,
re-extracted SDK. The original install prefix, exported SDK and source workspace
are hidden during execution. The selected CEF recipe's fixed local smoke performs
browser/renderer checks, JavaScript and expected-pixel validation. Windows needs
three fresh successful runs, Linux one; failures cannot be retried into success.
The new manifest binds the consumer evidence, CEF contract and SDK ZIP digest.
The private publisher independently checks that contract against the signed plan
and against the actual installed CEF package. It never executes SDK code.

## Explicit limitations and activation

This implementation supports **engine-static**, not a qualified fully static
third-party SDK. Linux still needs the declared system GLib/NSS/X11/ALSA stack.
The `static-third-party` profile is recognized by the schema but intentionally
rejected before source compilation/import; no downgrade or success claim occurs.
Static NSS/D-Bus, Xorg, CUPS, GBM/DRM, udev/PCI, plugin closure and a complete final
ELF/PE audit remain required. Existing Vulkan/OpenGL dependencies must also be
reviewed across the entire package graph. Sandbox/GPU are not certified.

The aggregate SDK limit remains 1900 MiB and the safe archive limit 12 GiB. A
larger SDK fails explicitly; multipart final-SDK publication is not implemented.
Source sync, checkpoint compression/encryption and final qualification need time
outside the compilation slice; large first builds may need smaller slice budgets
and runners with more disk. The source recipe's 80 GiB startup check still applies.

Review and merge the CEF adapter, private vcpkg port/consumer, builder and private
publisher changes together. Set one reviewed `BUILDER_COMMIT_SHA` consistently in
all three repositories only after review. Keep `PUBLISH_ENABLED=false` for the
first real two-platform run. No variables, keys, main branches, tags or releases
are changed by this implementation PR.

Continuation currently uses a NEW signed request from a new private stable tag
with updated selectors. Do not rerun a checkpoint producer; the canonical worker
rejects attempts greater than one. Do not reuse a tag to change a signed plan.
Automated continuation dispatch and cross-repository migration are not enabled.

## Tests

`python -m unittest discover -s tests -v` runs synthetic acquisition, real Tink
cache round-trips, corruption, domain separation, provenance and existing release
security tests. CI sets `REQUIRE_TINK_TESTS=1`; missing Tink is a failure there.
Local skips are not counted as passed cryptographic tests. These tests do not
substitute for an actual CEF source-resume cycle or a complete private SDK build.
