# Independent consumer publication

`publish-consumer-release.yml` and `secure_release.consumer_publisher` implement
the consumer-only orchestration over the existing approval, direct-result and
upload primitives. The SDK publisher is unchanged. The consumer source, native
executables and inner archive are **never executed** by this workflow.

## Trust and credential boundaries

- Dispatch only the immutable `consumer-publisher-<FULL_BUILDER_SHA>` tag matching
  protected variable `CONSUMER_RELEASE_BUILDER_SHA`. Enable explicitly with
  `CONSUMER_RELEASE_ENABLED=true`. The workflow and Python guard independently
  require the builder repository identity, approved actor, exact ref/SHA and
  attempt 1. Keep the route disabled until code review and synthetic CI pass.
- Configure environment `consumer-publication` to permit only that exact tag.
  Use its protection/reviewer rules as appropriate to the operator's authority.
  Never allow a PR/head branch to receive its secrets.
- `CONSUMER_RELEASE_POLICY_B64` is base64 canonical JSON with exactly:
  `schema`, `repository`, `repository_id`, `operator_id`, `source_sha`, `base_sha`,
  `qualifier_sha`, `run`, `tag`, `archive_name`, `archive_sha256`,
  `consumer_policy_sha256`, `signer_fingerprint`, and `acceptance`.
  `acceptance` contains nonempty explicit check-name lists for `dataplane`,
  `client`, and `supplier`. Missing, extra, skipped or failed checks cannot pass.
  Source, run, version, archive and signer are independently protected policy,
  never selected by copying an incoming approval.
- `consumer_policy_sha256` pins the canonical existing `CONSUMER_CI_POLICY_B64`.
  Source repository name/ID/operator must agree. Qualification is re-resolved
  from its original signed encrypted request and the complete GitHub aggregate:
  all eight executed lanes, exact immutable qualifier, first attempt and unique
  request. Historical expiry is checked at independently resolved admission time;
  neither original timestamps nor the old request are edited or re-signed.
- Only the verification step receives the existing input private recipient,
  request verification public key and **dedicated**
  `CONSUMER_CI_PUBLISH_PRIVATE_KEY_B64`. The latter decrypts the original
  `publisher-results.enc` directly; qualification still receives only its public
  recipient. No master-log key, delegated file key or capability is accepted.
- `CONSUMER_RELEASE_VERIFY_PUBLIC_KEY_B64` contains an independently approved
  armored OpenPGP **public** signer, base64 encoded. Its primary fingerprint
  must equal policy. Signing private keys/passphrases remain local and are never
  provisioned to any Actions job.
- Only the later publication step receives existing `BIN_PUBLISH_TOKEN`, as
  `CONSUMER_RELEASE_PUBLISH_TOKEN`. There is no SDK/default-token fallback.
  This process re-verifies every asset and the verification receipt, then checks
  live qualification before writes. Decryption keys are absent from its step env.
  Consumer code cannot run before or after this boundary.

GitHub tokens, environment protection and repository collaborators are operator
trust boundaries. A repository administrator able to replace approved code,
protected policy and secrets can change authority; this protocol does not claim
to defend against its own administrator.

## Artifact and signature chain

The verifier selects exactly `consumer-output-static-<QUALIFIED_RUN>-1` from the
authenticated run API, rejects expiration/duplicates, verifies the API ZIP digest
and bounds, and consumes only `publisher-results.enc`. Expected Tink context is
derived from authenticated qualification, not from the envelope header.

Only the expected five original result members are accepted. The exact approved
inner archive is copied byte-for-byte, its checksum and `result.json` checked.
Links, duplicate/foreign paths, sparse files and oversized PAX/GNU metadata fail.
No consumer logs are placed in release assets.

The release contains exactly eight files:

- The original archive and its detached `.asc` signature.
- `release-approval.json` and its signature.
- `provenance.json` and its signature.
- `SHA256SUMS` and its signature.

Provenance is canonical output of `provenance()`: independently verified
qualification/approval identity, original API artifact ID/ZIP digest, pinned
recipe/input inventory and signer. It does not include raw operational evidence.
`checksum_bytes()` deterministically hashes the archive, approval and provenance.
Every signature is verified in an isolated keyring; archive verification streams
bounded private staging rather than reading gigabytes into a Python object.

The operator prepares a UTC signed annotated tag for the exact qualified commit.
The workflow recomputes its Git object ID and verifies the pinned signer.
Only after full verification does the publication step create that exact signed
Git object/ref if absent. It validates server serialization before creating the
ref, never replaces a conflicting tag, and rechecks actual tag bytes/signature.
GitHub's generic `verified` flag is not release authority. The raw object may be
reconstructed from API verification fields or UTC tag metadata, but exact object
hash and independent OpenPGP verification are mandatory in both paths.

Only an identical draft may resume. The uploader snapshots approved bytes,
rejects extra/conflicting assets, downloads and hashes the remote files before
finalization, and verifies again afterwards. It never deletes/overwrites assets
or changes the latest-release designation. Existing other tags/releases remain
untouched. An interrupted run may leave a verified signed tag and/or draft;
retry only the identical signed bundle, not a modified asset inventory.

Remote tag, qualification and asset operations are not one atomic transaction.
The workflow serializes its own publications and rechecks qualification after
publishing, but cannot prevent a repository administrator mutating remote state
concurrently. A mismatch is failure, not permission to overwrite or hide it.

## Local preparation and dispatch

Complete the independently reviewed acceptance first. Each canonical receipt has
schema 1, purpose `consumer-release-acceptance`, kind, the exact source/qualifier/
run/attempt/archive identity and precisely the protected check-name inventory,
all `pass`. Sign the canonical approval binding their SHA256 digests. Never
replace missing checks with declarations merely to proceed.

Keep a private canonical bundle containing:

- `qualification_request` (original ciphertext) and `qualification_request_id`.
- `approval`, `approval_signature`, `tag` (base64 exact bytes).
- `receipts`: each of the three canonical receipt byte strings, base64 encoded.
- `signatures`: base64 detached armor for `archive`, `provenance`, `checksums`.

Sign locally using the approved key and the deterministic helpers above. Archive,
checksum and provenance signatures do not grant authority on their own: the exact
independently resolved approval/tag/receipts are required too. Preserve original
signature bytes for identical-draft continuation.

Encrypt only to the existing builder input **public** recipient:

```sh
python -m secure_release.consumer_publisher package \
  --bundle /private/consumer-bundle.json \
  --input-public /private/builder-input-public.json \
  --publisher-sha FULL_REVIEWED_BUILDER_SHA \
  --output /private/new-consumer-dispatch.json
```

The output contains an encrypted request, digest and immutable workflow ref,
ready for `POST /repos/dobord/builder/actions/workflows/publish-consumer-release.yml/dispatches`.
Do not print the plaintext bundle. The original HPKE message-size limit remains
unchanged; keep the complete inner request below 24 KiB. Publication transport
expires after six hours. Resume via a fresh encrypted publication request,
never an Actions rerun and never a replacement qualification.

## Cleanup and diagnostics

All plaintext assets and verification receipts live under owner-only
`RUNNER_TEMP/consumer-publication`, removed on success/failure. Only bounded error
class/frame/status records are encrypted to the existing log **public** recipient
and uploaded. Plaintext archive, source, profiles, receipt bodies and credentials
are never workflow artifacts. Key material is not printed or written by this
route. Python does not promise secure memory erasure.

## Validation scope

Synthetic tests use freshly generated Tink recipients and OpenPGP signers,
real direct-result decryption and signature verification, and an in-memory
destination API for signed-tag creation, draft continuation and remote byte
verification. Negative cases cover policy/source/signer/receipt/tag/artifact,
expiry, state/assets tamper and workflow credential/pin boundaries.

These tests prove the product contracts, not an actual release, token scope,
acceptance of a real candidate or permission to publish one. Actual publication
requires separately provisioned trust and explicit operator approval of every
gate. The broader publication issue remains open until readiness is reviewed.
