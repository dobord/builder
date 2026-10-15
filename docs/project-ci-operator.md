# Local operator project qualification (schema 2)

Schema 2 supports authoritative project qualification entirely in
`dobord/builder` (repository ID `1372874997`) while source Actions remain disabled.
It is an explicit transport protocol, not a fallback for schema 1. Schema 1 still
requires its original source Actions run, attempt and artifact provenance.

## Ownership and admission

The Linux local client `secure_release.project_ci_operator` owns packaging,
transport publication, dispatch and final status mirroring. It executes Git data
operations only, never source scripts, builds or tests. Builder prepare owns
signature, source-policy, baseline and automated OSV admission. Native builder
jobs own all authoritative qualification. Local tests are diagnostic evidence.

The independently configured policy JSON in builder is stored as opaque Base64
under `PROJECT_CI_SOURCE_POLICY_B64`, passed as `CI_SOURCE_POLICY_B64` and
decoded only inside trusted prepare. This prevents Actions' structured-secret masking from
classifying short schema values such as `2` as secrets in the public matrix.
Masking remains enabled; no private policy data is exposed through job outputs.
The policy must
retain its repository, repository ID, authorizer branch and ordinary CI approval
boundaries, and explicitly add:

```json
{"operator_origin":"local-operator","operator_id":5323024,"request_schemas":[2]}
```

These fields extend the existing policy; this fragment is not a replacement
policy. The client receives a protected local copy for preflight. Builder checks
its own policy, the signed operator identity, workflow actor ID, run actor and
triggering actor. A PR must be open, same-repository on both sides, and match the
exact current head/base; its base branch must match the policy's authorizer
branch. A non-PR must name exact current source main as both
head/base. Schema 2 queries no source Actions API. Ordinary CI retains sensitive
current-head independent review requirements; release adds no manual approval.
The optional `request_schemas` field is a nonempty, unique list drawn from
`[1, 2]`. Setting `[2]` denies legacy source Actions origins before any admission
API call, both in prepare and local policy preflight. Policies omitting the field
retain legacy admission behavior. Candidate requests cannot override this policy.

The source-read token in builder reads only source identity, PR/review policy and
published stable baseline metadata. The builder read token fetches the public
input Git objects. Native build commands retain their credential-free contract.
The local authenticated GitHub CLI account needs source metadata/content read,
source commit-status write, and builder contents/actions read/write permission.
Its token is captured in memory and never printed, saved or passed to build/test
commands. Existing cryptographic roles and SDK backups are unchanged.

## Noninteractive execution and Windows compiler diagnostics

Approved source commands always receive null stdin. Output remains in private
files. Wait errors and interruption trigger retirement while preserving the
original exception, even when cleanup or cleanup logging fails. A bounded timeout
observer may collect private diagnostics before retirement; observer failure
cannot bypass the retirement attempt or expose its exception text.

On Windows, both project CI and SDK supervision own each command through a
non-inherited kill-on-close Job Object. An absolute trusted launcher runs under
the official Python runtime with `-I -S` and blocks on a private one-byte handoff.
The supervisor assigns the launcher to the job before sending that byte; only
then may the launcher execute the approved command, with null stdin. The handoff
contains no environment, keys or credentials. No breakaway permission is granted.
Nested-job support requires Windows 8 or newer, including the hosted Windows
runners. Failed assignment fails closed; it never launches source unowned.

Job ownership survives root/launcher exit and timeout observers. Retirement
terminates the job, bounds observation of its active-process count, closes the
job handle, and reaps the parent. Normal Windows command completion also retires
remaining background nodes. An external unowned `Popen` compatibility path still
uses `taskkill`; its failures are reported and parent reaping is always attempted
with a bounded wait. This PID-based path does not guarantee descendants after
parent exit. Admitted
commands use the owned-job path. Real nested-job, parent-exit and SDK-consumer
behavior requires native Windows qualification; synthetic mocks are insufficient.

Every Windows `qualify` lane has a mandatory pre-materialization native ownership
gate. It uses only the standard library and the reviewed public
`NativeWindowsOwnershipTests`, under an allowlisted credential-free environment.
Exactly the two required tests must run and succeed: cancellation before first
wait (including source stdin EOF), and grandchild retirement after parent exit.
Skips, expected failures, missing tests and other failures block materialization
and qualification. No extra job is introduced; the required 39-lane inventory
and lane names remain unchanged.

The gate's unittest output and summary stay under
`runner.temp/project-ci-native-contract/`, separate from source staging so failed
preflight does not create or decrypt a source checkout. Existing always-run
encrypted diagnostics collect this directory, and existing cleanup removes it.
Public output is limited to fixed gate status. The gate has a three-minute step
deadline and cannot silently substitute mocked results for native execution.

Before recognized PowerShell Visual Studio configuration steps, the admitted
runner performs one public synthetic C++ compiler-identification smoke check per
generator/architecture. Generator and architecture come from the admitted command
and bounded local preset inheritance; the unqualified default is selected only
for `windows-2022`. MinGW, Ninja and non-Windows commands retain their own paths.
Preset includes, external architectures and toolset overrides require explicit
probe support before use; they are not silently replaced by another toolchain.

The primary smoke check has a 90-second cap. On failure, controls compare
`WINDIR`, explicitly allowlisted Windows host inputs, and direct CMake execution;
successful host-input controls permit bounded single-variable comparisons.
All use null stdin. Controls have 45-second caps, single-variable checks 10 seconds,
and the complete probe shares a 300-second budget within the existing lane
deadline, reserving 130 seconds for snapshot and worst-case process-tree retirement
(30 seconds for each native killer and each child wait). Controls may be omitted
or shortened when this reserve would otherwise be consumed. A failed
primary check always fails the lane, even if a control succeeds. Controls never
modify the original recipe environment, feature options, recipe bytes or pins.

The private `project-ci/windows-compiler-<step>/` directory retains a summary,
configure logs, installed-CMake compiler-module tracing without expression
expansion, and timeout process names/PIDs/parent PIDs. No environment dump,
process command line or owner is queried. Existing authenticated encrypted-log
collection carries these files; no plaintext artifact or public report is added.
This is diagnostic hardening, not proof that a historical Windows hang is fixed.
Native exact-SHA qualification and all 39 release lanes remain mandatory.

## Private prepare-failure diagnostics

Prepare failures retain a bounded owner-private record before the fixed public
stage-failure marker. It contains exception type, an exact allowlisted reason,
and at most 16 sanitized module/function/line entries from a bounded stack walk.
An HTTP error may add only an integer status from 400 through 599. No arbitrary
exception string, chained exception, local, source line, path, URL, header, body,
request, environment or key bytes are recorded. Unknown/invalid strings use fixed
placeholders. These code identifiers are metadata, not DLP/content inspection.

Fresh exclusive staging uses POSIX directory/file modes `0700`/`0600`; Windows
inherits the trusted runner temporary directory's ACLs. Links, overwrites,
hardlinked records and broadened POSIX permissions are rejected. Recording errors
cannot replace admission failure or expose diagnostic exceptions publicly.

The same reviewed Tink encrypted-log context and public log recipient encrypt
prepare diagnostics in always-run steps; only `.enc` is uploaded before always-run
plaintext cleanup. A fixed `no-prepare-error-record` header covers absent records
(including pre-prepare installer failure) without asserting successful admission.
If the reviewed crypto runtime itself is unavailable, encryption/upload fail
closed: no plaintext or alternate cipher is published. Failure still blocks all
qualification lanes; source/input uploads retain their implicit success guard.
Diagnostics do not authorize replay: retry needs a fresh signed request/nonce and
any implementation change needs a newly reviewed immutable builder revision.

## Source-backed coverage report names
Report collection keeps the credential-like filename guard. A narrow exception
admits direct-child `coverage.<C/C++ basename>.<gcovr MD5>.html` pages only when
bounded gcovr format `0.6` metadata maps the exact name to an existing, nonlinked
C/C++ source inside the materialized source tree. Missing, malformed or unsupported
metadata grants no exception; raw credential-like files, key-source extensions,
unmapped/wrong-hash HTML, nested pages, links and escaping paths remain rejected.
Metadata is capped at 64 MiB and 20,000 records; archive bounds are unchanged.

The approved recipe output and materialized source are trusted inputs. This is
filename classification for private source-coverage reports, not HTML body/DLP
inspection. The MD5 is only gcovr's existing filename identifier, explicitly not a
security digest. SHA-256 archive manifests, source/lane binding, recipient roles,
authenticated context and ciphertext-only publication remain unchanged.

## Signed transport

The strict schema-2 field set is:

```text
schema request_id source source_id source_sha base_sha builder_sha suite pr
created expires origin operator_id baseline_tag baseline_sha
input_commit input_blob input_ref source_cipher_digest
```

There are no source run, attempt, event or artifact placeholders. The exact
reviewed builder SHA must resolve from an operator-supplied immutable builder
tag; both package/dispatch and final verification revalidate that ref.
The previous-release baseline must be published, non-draft and stable; its
peeled commit SHA is independently revalidated by builder. Release/performance
cannot compare the candidate against itself.

Private staging holds a full Git bundle fetched into a fresh bare repository,
with system/global config, hooks and credential helpers disabled. There is no
checkout or attribute-filter execution locally. Inert recipe YAML supplies the
expected lane inventory. Plaintext bundles and Git objects are removed on
successful packaging; failed staging remains private for operator cleanup.

### Builder-owned release recipe contract

The reviewed builder code pins SHA-256 of the exact recipe bytes for all five
release profiles: `ci`, `wasm-async`, `nightly-stress`, `performance`, and
`vcpkg-port`. Local packaging and builder `recipes()` share the same admission
helper: all five must be present and match the builder-owned pins before any
YAML parsing or lane expansion. Every native job also rechecks this contract.
The 39-lane count remains a secondary consistency check; it cannot authorize
replacement commands, omitted profiles or altered runner platforms.

Pins are neither candidate-provided nor policy/environment/CLI overrides. Any
recipe-byte change, including comments or line endings, requires review and a
new builder revision containing updated pins. The public contract contains only
generic profile names and digests, not private recipe content or package names.
It authenticates recipe bytes, not all source code or scripts invoked by those
recipes; normal exact-source admission and complete hosted qualification remain
necessary. Non-release profiles retain policy-authorized recipe flexibility.

All profiles use bounded matrix parsing: validated dictionaries/lists/scalars,
at most 16 dimensions or include-row fields, at most 100 values/include rows,
and Cartesian cardinality checked against the remaining lane budget before
calling `itertools.product`. The cumulative budget is 100 across jobs and
profiles; recipe input is at most 1 MiB per profile. Both local packaging and
prepare use these same bounds.

Existing official Tink HPKE plus Streaming AEAD encrypts the bundle. Only
`sources.enc` is sent to the fixed builder Git Data API. It is at most 90 MiB,
below the 100 MB API limit. A parentless commit has a root tree containing
exactly one `100644` blob named `sources.enc`. Its message is generic, and the
ref is `refs/tags/project-ci-input-UUID`. No source repository name, source
revision, baseline metadata or plaintext archive enters public Git.

The signed payload binds the exact commit, blob, opaque ref and ciphertext
SHA-256 digest. Prepare checks both ref snapshots, commit identity/no parents,
tree identity/no truncation/single entry, blob mode/type/SHA/base64 encoding and
size, recomputed Git blob SHA and SHA-256 digest before publishing staging output.
The public file-envelope context contains only schema, distinct operator purpose,
opaque request UUID, public builder ID and reviewed builder SHA. The signed
metadata is HPKE sealed with a distinct schema-2 request context. The workflow
receives `request_schema=2`; it never tries another schema after a failed decrypt.

Replay detection requires exactly one request-digest run, this current run, and
attempt 1. Dispatch failure or an Actions rerun requires a fresh package/request;
there is no context override. Prepare re-encrypts sources and the signed request
for this builder run/attempt before distributing to native jobs as usual.

## CLI stages (paths only for keys)

Use the existing hash-pinned project-CI Python environment, authenticated `gh`,
an owner-only staging parent, and regular owner-only policy/private signing files
outside Git (normally `0600`). Public input and signing key files may be `0644`:
they must be owned by the operator, regular, non-symlink, bounded, and not writable
by group/others. `--work` must be a new directory at package time. The example is deliberately
not executable until the operator supplies the exact reviewed revisions/paths:

```sh
/tmp/opencode/project-review-venv/bin/python -m secure_release.project_ci_operator package \
  --work /private/staging/project-ci-fresh-request \
  --policy /private/config/source-policy.json \
  --pr 151 --suite release --baseline-tag v0.4.0 \
  --source-sha EXACT_40_HEX_SOURCE_HEAD --base-sha EXACT_40_HEX_PR_BASE \
  --builder-sha EXACT_40_HEX_REVIEWED_BUILDER_SHA \
  --builder-ref refs/tags/IMMUTABLE_REVIEWED_BUILDER_TAG \
  --signing-private /private/keys/request-signing-private.json \
  --input-public /private/keys/builder-input-public.json

/tmp/opencode/project-review-venv/bin/python -m secure_release.project_ci_operator dispatch \
  --work /private/staging/project-ci-fresh-request \
  --signing-public /private/keys/request-signing-public.json

/tmp/opencode/project-review-venv/bin/python -m secure_release.project_ci_operator wait \
  --work /private/staging/project-ci-fresh-request \
  --signing-public /private/keys/request-signing-public.json
```

Package publishes encrypted input transport but does not dispatch. Dispatch
uses the sealed request in owner-only `state.json`, and refuses an existing
matching run or local dispatch marker. The lane inventory, payload, request
digest and builder ref have an additional local Ed25519 signature; dispatch/wait
verify it against the separately supplied signing public key.

Wait verifies exact builder repository/workflow/SHA/request digest, actor,
attempt 1, completed successful run, exact expected native job inventory and
successful `prepare` plus `Encrypted qualification required` aggregate. Release
requires all 39 native lanes. It rechecks input provenance, immutable builder
ref and the current run attempt before writing source status
`Builder release Required` (or `Builder ci Required` for CI). Missing, skipped,
cancelled or failed qualification cannot produce a success status. Only this
local tool holds status-write credentials; builder jobs do not mirror status.

Output is bounded stage outcome, request digest and verified builder run URL.
Detailed qualification evidence is saved locally in owner-only
`qualification.json`. No automatic input-tag deletion occurs before or after
qualification; retention/removal is an operator responsibility. Six-hour signed
request expiry is enforced throughout; expired work needs a fresh request.

## Validation and handoff

```sh
/tmp/opencode/project-review-venv/bin/python -m unittest \
  tests.test_project_ci_contract tests.test_project_ci_operator tests.test_project_ci \
  tests.test_project_dependency_review -v
git diff --check
```

The reviewed builder revision containing this implementation, its immutable ref,
enabled builder qualification configuration and extended source policy must be
established by the owning operator before a real dispatch. This client never
enables source Actions, provisions secrets, creates a source release tag or
publishes release artifacts. Full hosted synthetic qualification and final
exact-source release evidence remain required.
