# Encrypted Docker endurance qualification

## Separate bounded-drive integration pilot

The isolated `ci/encrypted-drive-foundation` branch may also execute a signed
`mode=pilot` request for the reviewed Docker drive-integration recipe. Its job has
a 90-minute build/test budget; this is **not** a change to the five-hour file
qualification contract or the accepted duration/cycle values. The existing
foundation mode still has `qualification=false`, the exact foundation recipe and
`drive_interoperability=NOT RUN` guards. Its historical runs remain foundation-only.

An integration pilot must retain its own source inventory, image and live-client
library hashes, actual FUSE/native-client and GUI/video effects, read-only negative
matrix, active-consumer interval and final resource cleanup. It must continue to
report `qualification=false`; no Windows, installed-MAC or endurance qualification
is inferred. Input/evidence purposes, recipient/signature checks, data-only input
commit boundary and repository/ref/attempt/SHA guards are unchanged. Do not put
private recipes, revisions, stand credentials or plaintext results into this public
workflow or its inputs. The separate `DRIVE_FOUNDATION_CI_RUN_SHA` variable remains
the exact isolated-branch admission guard; other workflows/variables are untouched.

The private source envelope must contain all product files needed by its recipe.
No product repository token is passed to the recipe. Fetch only public pinned
upstreams; if build tooling needs Git metadata, create disposable staging metadata
and record it separately from the authenticated product source revision/inventory.
An unauthenticated private Git fetch failure is not an integration result and must
remain a retained failed request, followed by fresh operator authorization/input.

The retained qualification protocol requires **18000 seconds / 100 cycles**.
It needs a separately reviewed 360-minute workflow budget to leave up to one hour
for preparation, teardown, encryption and upload. The current isolated pilot
workflow has only 90 minutes and **cannot execute or qualify that full profile**;
the generic CLI's ability to package it is not runtime evidence or a budget gate.
A timed-out or partially completed job is FAIL; a short pilot is never a five-hour
qualification.

## Approval and transport

1. Review/commit the public workflow/module changes as code commit **B**.
2. Package the exact private working-tree snapshot outside the source worktree,
   using the operator's protected SDK-role backups. Only key file paths are passed:

   ```sh
   python -m secure_release.docker_endurance package \
     --keys /protected/release-keys --source /protected/source \
     --repository OWNER/PRIVATE_SOURCE --repository-id IMMUTABLE_ID \
     --builder-code-sha FULL_CODE_SHA --recipe ci/docker-recipe.py \
     --mode qualification --duration-seconds 18000 --cycles 100 \
     --output ci/docker-endurance-input.enc
   ```

   The existing official Tink envelope and Ed25519 signature are reused, with
   distinct authenticated input/evidence purposes. No crypto algorithm, lockfile,
   SDK publication policy or release flag changes. The source base Git SHA and the
   actual snapshot digest are both signed: a dirty snapshot is not represented as
   pristine committed source. Upstream acquisition belongs to the approved recipe.
3. Make data-only commit **C**, directly after B, changing only
   `ci/docker-endurance-input.enc`. No plaintext names/revisions/recipes enter the
   public branch or workflow inputs. Only this encrypted file leaves packaging.
4. Set the isolated `ENDURANCE_CI_RUN_SHA` variable to C before pushing C to
   `ci/encrypted-docker-endurance`. Existing main, release and project-CI settings
   remain independently controlled. The workflow refuses any other SHA, rerun
   attempt, additional code change, wrong purpose or expired signature.

The workflow uses isolated `ENDURANCE_CI_INPUT_PRIVATE_KEY`,
`ENDURANCE_CI_VERIFY_PUBLIC_KEY` and `ENDURANCE_CI_INPUT_PUBLIC_KEY_B64` secrets,
provisioned through `gh` stdin from the operator's same-role backups. Validate
those input/signature key pairs locally before dispatch; SDK/project-CI secrets
are neither replaced nor required by this experimental workflow.
An unconfigured variable makes the job SKIP, which is not acceptance evidence.

## Execution and evidence

The recipe sees neither signing/decryption keys nor Actions tokens/file commands.
Its stdout/stderr are captured privately. Approved code is trusted; environment
filtering is not an adversarial sandbox. Recipes must keep product builds and
runtime inside disposable Docker containers, preserve exact image/client/source
provenance, and produce `endurance-result.json` plus per-cycle evidence.

Admission bounds source files, expanded size, paths and Git/code identity before
execution. Crypto/context/recipient validation is fail-closed. The reviewed source
recipe must independently check wall-clock duration, all cycle byte/hash oracles,
stable session ownership and final cleanup. The wrapper then checks exact mode,
duration/cycle counts and completion before accepting PASS.

Only `evidence.enc` is uploaded, including failure diagnostics and partial-cycle
results. Source metadata stays in ciphertext. Authenticate decryption with the
operator-supplied run, attempt and exact builder C SHA; do not use an envelope's
claimed context as the expected context. Clean local plaintext after diagnosis.
There is no publication, support promotion, automatic issue closure or main update.

For development use `--mode pilot --duration-seconds 60 --cycles 2` and a fresh
encrypted data-only commit. Every full run also needs a fresh signed request;
Actions reruns do not reuse an old authorization. If GitHub force-cancels a job,
the normal encrypted finalizer may not finish: missing ciphertext remains FAIL,
never an inferred successful or resumable qualification.
