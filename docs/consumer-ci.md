# Independent encrypted consumer qualification

This contour has its own workflow, policy and key settings. It does not replace
`encrypted-project-ci.yml`, change its source policy or qualify its release
recipes. It authorizes qualification only, never release publication or merge.

## Trust model

The operator reviews the public builder revision and the private consumer tree.
The consumer's `ci/builder/consumer.json` must match a SHA-256 stored independently
in `CONSUMER_CI_POLICY_B64`. All eight lanes (`gcc`, `clang`, `asan`, `tsan`,
`ubsan`, `static`, `offline`, `browser`) are mandatory and use GitHub-hosted
Ubuntu 24.04. Each lane has exactly the fixed command
`bash ci/builder/qualify.sh LANE` and a bounded timeout. Recipe authenticity
does not independently review every source script or upstream package.

The local operator signs an exact source/PR/base, request ID, expiry, builder
revision and source ciphertext identity using the existing Tink request
signature implementation. The separate input encryption role seals the request
and exact head/base Git snapshot bundle. The source fetch has depth one: retired
files and unrelated history are not retransmitted. Original commit/tree IDs
remain verifiable. Only `sources.enc` in an opaque parentless Git input
commit is public. Inputs are bounded to 90 MiB and requests to six hours.

Trusted preparation verifies the source repository ID, private visibility,
current head/base and operator identity through the source-read credential.
It rejects replay, wrong workflow/actor/builder, changed refs and reruns.
It fetches only independently provisioned immutable Git inputs and
checksum-pinned release assets. Native jobs reauthenticate the source,
recipe and resource inventory, verify Git objects and asset hashes, and
reject linked/escaping/oversized SDK ZIPs before execution. Preparation
rechecks the source identity before distributing run/attempt-bound encrypted
inputs. Candidate code cannot select resource repositories or URLs.

Native commands receive allowlisted host variables plus input/result locations
and source/base IDs. They do not receive API credentials, private keys, Actions
file-command channels or the source policy. They have null stdin, private
stdout/stderr and process-tree retirement at a bounded timeout. Reviewed source
and compiler code is trusted: this is not an adversarial sandbox, and hosted
sudo/network access is not a security boundary against malicious approved code.

Diagnostics and bounded result archives use the committed log recipient and
existing Tink streaming envelope. Only ciphertext is uploaded. Result context
includes lane, request, builder, run and attempt. Plaintext cleanup always runs.
The operator's one-shot verifier requires all eight native jobs and the prepare/
required aggregates, successful executed recipe steps, exact run/attempt, an
unchanged input ref and current source PR before mirroring a commit status.

This contour authenticates pinned dependency inputs; it does not inherit the
other project's OSV inventory or performance/40-lane release qualification.
Supplier/advisory review, genuine device/dataplane acceptance and release
signing remain separate gates. Missing tests must be reported, not relabeled.

## Independent provisioning

Provision new settings without overwriting any existing project/SDK setting:

- `CONSUMER_CI_POLICY_B64`: protected Base64 JSON with exact keys `schema: 1`,
  `repository`, numeric `repository_id`, `operator_id: 5323024`,
  `recipe_sha256`, and one to eight `inputs`.
- `CONSUMER_CI_INPUT_PRIVATE_KEY_B64`: input-role Tink keyset.
- `CONSUMER_CI_VERIFY_PUBLIC_KEY_B64`: request-signing public Tink keyset.
- `CONSUMER_CI_BUILDER_SHA`: reviewed immutable builder commit.
- `CONSUMER_CI_ENABLED`: initially `false`; activate only after review.

An input is either `{name, kind: "git", repository, sha}` for a bounded immutable
Git bundle, or `{name, kind: "asset", repository, tag, asset, sha256, max_bytes}`
for a published stable release asset. The total declared bound cannot exceed
2 GiB. Resource names are simple, unique `.bundle`, `.zip` or `.json` basenames.
Materialization retains each already authenticated `.bundle` alongside its
generated `.tar.gz`. A native toolchain bootstrap can restore the approved
shallow commit from these Git objects without private network access; it must
verify the expected revision rather than manufacture a new commit from a tar.
The existing `SOURCE_READ_TOKEN` is used only by preparation; it needs read
access to the selected source, PR metadata and pinned inputs. No token is
copied from the operator account or exposed to native jobs.

Private keys stay outside Git and are passed only as filesystem paths to the
operator. Explicit operator authorization may reuse existing SDK keypairs for
the same input/signing roles; never use a transport signer as implicit release
signing authority. Shared-key compromise affects both contours.

## Local client

Use the reviewed hash-pinned Python runtime and authenticated `gh`. Policy,
signing-private and staging paths are owner-only; public key backups must be
owner-controlled, regular, bounded files. The builder ref must be an immutable
tag resolving to the reviewed SHA.

```text
python -m secure_release.consumer_ci_operator package --work NEW_PRIVATE_DIR \
  --policy PRIVATE_POLICY --pr NUMBER --source-sha SHA --base-sha SHA \
  --builder-sha SHA --builder-ref refs/tags/REVIEWED_TAG \
  --signing-private PRIVATE_KEY_PATH --input-public PUBLIC_KEY_PATH
python -m secure_release.consumer_ci_operator dispatch --work PRIVATE_DIR \
  --signing-public PUBLIC_KEY_PATH
python -m secure_release.consumer_ci_operator verify --work PRIVATE_DIR \
  --signing-public PUBLIC_KEY_PATH
python -m secure_release.consumer_ci_operator fetch --work PRIVATE_DIR \
  --signing-public PUBLIC_KEY_PATH --lane static --output NEW_PRIVATE_OUTPUT \
  --output-private PRIVATE_LOG_KEY_PATH
```

`package` publishes encrypted transport, not a workflow run. Dispatch is
single-use. `verify` is one-shot: pending, failed, cancelled, missing or skipped
work cannot create success. A new request is required after a failed dispatch,
expiry or any Actions rerun. The operator retains the encrypted input tag
until explicit cleanup. Do not publish local state, policy or decrypted logs.

`fetch` requires the complete successful aggregate, checks the GitHub artifact
digest, decrypts with the expected request/run/attempt/lane context, validates
archive paths and the exact-source result receipt, and publishes plaintext only
to a new local directory. The supplied output private key stays local. This is
artifact verification, not authorization to publish a release.

## Consumer publication approval contract

`resolve_qualification` decrypts and authenticates the original sealed request
with independently configured consumer transport keys. It checks protected
source policy and builder revision, then reads the exact run and all first-attempt
jobs from GitHub. All eight lanes and required commands must have succeeded;
duplicate request dispatches, reruns, changed runs and partial aggregates fail
closed. The current run is read again before returning its authenticated source
identity. No source checkout, consumer executable or write API is used.

Historical request expiry is checked at GitHub's run-creation timestamp. This
does not permit dispatching an expired request: preparation and operator paths
continue to validate against the current clock. A historical successful run is
qualification evidence, not approval to publish or proof of the later acceptance
records. Protected policy, API access and transport keys must be independently
provisioned; the approval cannot select them.

`consumer_publication.check_approval` validates a bounded canonical approval
document against independently resolved trusted inputs. It binds the
destination repository ID, signed tag object, source and base, exact builder
revision and first run attempt, request digest, archive name/digest, and the
three independent acceptance receipt digests (dataplane, client, supplier).
A qualification receipt or candidate provenance is not a publication approval.

`verify_signed_approval` additionally authenticates those canonical bytes using
exactly one detached Ed25519 OpenPGP signature. It uses GnuPG/gpgv with an
isolated temporary keyring, a separately provisioned public key and exact
primary-key fingerprint (signing subkeys are not admitted); ambient keys,
credentials and user configuration are not forwarded. SHA-1/MD5 signatures,
multiple signatures, expired/revoked signature status, missing tools and timeout
fail closed. Private signing keys
are not accepted or used. Tests generate only disposable synthetic signers;
their crypto cases explicitly skip where GnuPG tools are unavailable. A real
publication stage must require these tools rather than skip verification.
The synthetic signer uses a private passphrase file rather than an empty
command-line argument, including on Windows/MSYS. A small crypto smoke runs
before the complete hosted security suite so setup failures remain localized.
Tool-facing paths use forward slashes on Windows as well as POSIX systems.
When the selected Windows GnuPG has a sibling MSYS `cygpath.exe`, its temporary
home is translated into that toolchain's POSIX namespace; native GnuPG and
POSIX hosts do not require this translator. Invalid or failed translation is
an error, not permission to skip signature verification.
Setup diagnostics are bounded and strip paths and synthetic fingerprints;
production verification continues to discard raw GnuPG error output.

`verify_source_tag` authenticates bounded raw annotated Git tag bytes using the
same isolated pinned signer. It recomputes the Git object ID, requires a direct
commit target and the exact expected version/source, and checks the embedded
OpenPGP signature over the unsigned tag payload. Lightweight, nested, foreign,
tampered and unsigned tags are rejected. GitHub's generic `verified` metadata
does not substitute for this check. Callers must resolve the actual tag ref and
raw object independently; a caller-supplied object ID alone is not ref evidence.

`check_acceptance_receipt` requires a bounded canonical acceptance record with
the exact independently qualified source, builder, run, first attempt and archive
digest. Each of `dataplane`, `client` and `supplier` uses a separately protected
nonempty check inventory; every listed result must be exactly `pass`. Missing,
extra, skipped or `NOT RUN` results fail closed. The returned SHA-256 binds the
record to the signed publication approval. These are assertions, not synthetic
proof of actual packet paths or supplier review: the operator must review the
underlying private evidence before signing approval. Do not put raw operational
logs or real profiles into these records or publish them.

These validators do not acquire evidence, resolve its authority or upload anything. The
remaining publisher must obtain expectations from independently verified
evidence rather than the approval itself, resolve the complete qualification,
retrieve and recheck the tag ref, and perform scoped draft upload with
byte-for-byte verification.
The SDK publisher remains separate.

## Verified archive handoff

`consumer_handoff` can re-encrypt the exact locally verified archive to the
existing builder input **public** recipient using the unchanged Tink envelope.
It does not accept the operator log private key or any signing private key.
The original archive is neither rebuilt, extracted nor executed.

Callers must first independently authenticate the complete expected publication
approval. Transport alone grants no release authority. `seal_archive` snapshots
a bounded regular source and requires its exact approved name and SHA-256;
the authenticated encryption context binds the complete approval digest.
`open_archive` uses the builder input private recipient only in trusted staging,
authenticates every encryption tag and rechecks the exact plaintext SHA-256.
A valid encrypted envelope carrying the wrong archive is still rejected.

Private same-filesystem staging and atomic no-overwrite links prevent partial
outputs or replacement of an existing/racing destination. Linux staging must be
owner-only; the eventual production publisher is Linux-only. Temporary plaintext
and ciphertext staging is removed on success and failure. This is a library
primitive, not a command, workflow, upload operation or actual handoff proof.
Original run/artifact evidence and independent approval remain mandatory.

## Trusted upload primitive

`consumer_upload.publish_release` is a separate consumer-only library primitive.
It has no command/workflow or environment credential lookup. Only a future trusted
upload stage may call it, after independently verifying qualification, acceptance,
approval and asset signatures and deriving the authenticated asset inventory.
The destination-scoped API credential must never reach consumer code. The
existing SDK publisher is unchanged.

The inventory is exactly the approved archive and its `.asc` signature,
`SHA256SUMS` and its signature, `provenance.json` and its signature, and
`release-approval.json` and its signature. All local files are snapshotted in
owner-only staging and checked against their authenticated hashes before writes.
The approval file must equal the independently authenticated canonical approval.
The private repository identity and preexisting annotated tag ref are checked
before writes and again before finalization; this primitive never creates tags.

Publication starts as a draft marked by approval and inventory digests. Only an
identical owned draft can resume; missing assets are uploaded without replacing
or deleting anything. Conflicting bodies, names, metadata, extra/aliased assets
and incomplete published releases fail closed. Exact remote bytes are fetched
and hashed before draft finalization, not trusted from metadata alone. Storage
redirects are HTTPS-only to fixed GitHub asset hosts and do not receive API
authorization. A complete identical published release is verified without writes.
Finalization does not change GitHub's latest-release designation.

Interrupted uploads leave a resumable draft. Finalization and GitHub ref/asset
updates are separate remote operations, not one atomic transaction: callers must
serialize their own publisher and independently verify the final remote state.
The primitive checks assets again after publication and fails on inconsistency;
it does not delete others' assets, rewrite tags or claim recovery from concurrent
external mutations. Synthetic API tests do not prove actual scoped-token access
or authorize a live publication. Workflow/authority wiring remains unfinished.

## Original-artifact decryption capability

Archive re-encryption alone cannot independently prove its origin in an earlier
encrypted CI result. `consumer_capability` adds an explicit one-envelope
delegation primitive for that boundary, without changing the existing envelope
format, original header/recipient/context/ciphertext or `crypto.decrypt_file`.

The POSIX-local operator `create` reads protected master-log and operator-signing
key **paths** only. It refuses Actions execution before reading either key.
It snapshots the exact ciphertext, unwraps only that envelope's independently
random streaming file key and consumes every original AEAD tag to authenticated
EOF before issuing a capability. The delegated payload contains that file key, not the master-log or
operator signing private key. It is signed with the existing consumer operator
key and HPKE-encrypted to the builder input public recipient. Plaintext delegated
keysets must never be printed, persisted, placed in argv/environment, committed
or published. Only the encrypted capability may be transferred.

The binding includes the complete approval digest, exact builder/request/run,
first attempt, static lane, original artifact ID and ZIP SHA-256, ciphertext
SHA-256 and original log recipient fingerprint. The trusted receiver must derive
**all** those expectations independently from protected policy, authenticated
qualification and the original API-downloaded/digest-verified artifact. It must
never echo capability fields back as expected values. The helper itself takes
the extracted original ciphertext, not the ZIP or API credential; archive
retrieval and original-artifact provenance checks remain caller obligations.

`open_result` accepts only the builder input private key and independently pinned
operator public key. It verifies the encrypted signed capability and exact
ciphertext digest, keeps the original header/context/recipient checks and uses
the original Streaming AEAD AAD/tags unchanged. Authenticated EOF and bounds
precede atomic no-overwrite plaintext publication in private staging. Correctly
signed delegation with matching ciphertext hashes still cannot bypass corrupted
AEAD tags. Existing global-recipient decryption remains strict and cannot use the
builder input key to decrypt the original result without explicit delegation.

A capability authorizes reading one original result, not publishing a release.
The future workflow must additionally verify release approval, exact archive
bytes and signatures, acceptance and all original CI evidence before giving
scoped authority to the upload stage. No master key or real capability has been
provisioned in CI by this library change. Tests use fresh synthetic keys:
POSIX exercises the local creator, while Windows explicitly rejects unsupported
operator creation and exercises the receiver with a real Tink reference capsule.
Python does not promise secure erasure of in-memory key material.
