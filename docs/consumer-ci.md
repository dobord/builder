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
