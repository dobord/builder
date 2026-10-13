# Encrypted Docker endurance qualification

This opt-in branch workflow runs an operator-approved private source snapshot on
an ordinary `ubuntu-24.04` Actions runner. The qualification timer is **18000
seconds / 100 cycles**. The 360-minute job budget leaves up to one hour for
preparation, teardown, encryption and upload. A timed-out or partially completed
job is FAIL; a short pilot is never a five-hour qualification.

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

The workflow uses the existing input/signature secrets and the base64 public
input-key backup. Validate those same-role key pairs locally before dispatch.
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
