# Encrypted three-repository static SDK pipeline

Public automation for `dobord/vcpkg` -> `dobord/builder` -> `dobord/vcpkg-bin`.
Private project names, source revisions and package graphs live only in the source
repository's signed, HPKE-encrypted release plan, not in this repository.

## Trust boundary

The source repository only signs/encrypts a small request and dispatches this
repository. This repository does the actual Linux/Windows build. A separate
`workflow_run` handler dispatches the private publisher only after successful
completion. The private publisher independently checks the exact run, attempt,
workflow, approved commit, both artifacts, signatures and hashes.

Output SDKs and compiler logs use Tink HPKE X25519/HKDF-SHA256/AES-256-GCM to wrap
fresh per-file Tink Streaming AEAD `AES256_GCM_HKDF_1MB` keysets. A random 32-byte
request salt, release ID, run/attempt, purpose, platform and repository identities
are authenticated context. Salt is not a password or authorization credential.
The long-term output private key exists only at the private publisher and the
operator's protected backup. Input/request transport has a DIFFERENT keypair;
request authorization has a separate Ed25519 signing keypair.

This is NOT an offline sandbox: trusted, reviewed CMake/portfiles and compiler
processes see plaintext while building. Public dependency downloads remain
allowed. Environment filtering and ephemeral GitHub-hosted jobs are hygiene,
not isolation from malicious approved code. Do not admit untrusted code, change
release workflow permissions casually, or expose the long-term input key to PRs.
Public artifact sizes, timing and opaque release/run IDs are observable.

## Files

- `secure_release/crypto.py`: bounded versioned envelopes, signatures, atomic authenticated decryption.
- `safeio.py`: bounded archive validation; rejects traversal, links, reparse points and collisions.
- `tasks.py`: non-executing source fetch, static build, exported consumer tests, encrypted output.
- `publish.py`: independent verification, retry-safe draft handling, conflict refusal.
- `bootstrap.py`: LOCAL-only key generation and repository secret provisioning with `gh` stdin.
- `decrypt_local.py`: LOCAL-only authenticated diagnostic decryption; does not authorize releases.
- `fetch_sdk_local.py`: LOCAL-only download, verification and decryption of completed SDK artifacts.
- `.github/workflows/ci.yml`: PUBLIC synthetic tests only; disposable PUBLIC test keys protect no private data.
- `.github/workflows/build-release.yml`: real encrypted release build, disabled until configured.
- `.github/workflows/request-publication.yml`: dispatch publisher after completed successful build.

All actions are pinned by full SHA; crypto dependencies and CMake are wheel-only
and SHA256 pinned. Source and recipient repositories are fixed by immutable IDs.
No `pull_request_target`, no inherited release secrets, no shared private cache.
Only encrypted `.enc` files leave release jobs in this public repository. Never
upload plaintext diagnostics, source archives, credentials or private SDKs here.

## Installation

Use Python 3.12 on Windows x64 or Linux x64 and authenticated GitHub CLI with
administrator access to the three repositories. On the trusted operator machine:

```sh
python -m pip install --require-hashes --only-binary=:all: -r requirements.lock
python -m unittest discover -s tests -v
python -m secure_release.bootstrap generate --directory "$HOME/.vcpkg-release-keys"
python -m secure_release.bootstrap configure --directory "$HOME/.vcpkg-release-keys" --builder-sha FULL_REVIEWED_MAIN_SHA --prompt-tokens
```

Keys never print to stdout or command arguments. `configure` installs common
output PUBLIC keysets, separate private keysets in their intended repositories,
verification keys and narrow API credentials. It refuses noncanonical identities
and sets `RELEASE_ENABLED=false` everywhere and `PUBLISH_ENABLED=false` at the
publisher. It does not enable releases or create tags. Keep a secure backup of
the key directory outside any Git worktree; do not upload it to this repository.

The private source repository contains the complete Russian setup guide at
`docs/encrypted-release/SETUP_RU.md`, including the exact private source scopes,
permission settings and first validation-only run. Enable publication only after
the first complete two-platform verification succeeds.

## Local workstation SDK retrieval

A completed encrypted SDK can be fetched directly from the public builder without
enabling the private publisher. Keep the artifact-decryption private key in the
operator backup outside any Git worktree. The GitHub API token is read only from
`GH_TOKEN` (preferred) or `GITHUB_TOKEN`; private key material is read from a file.

Windows PowerShell example:

```powershell
py -m pip install --require-hashes --only-binary=:all: -r requirements.lock
$env:GH_TOKEN = gh auth token
py -m secure_release.fetch_sdk_local `
  --platform windows `
  --private-key C:\secure\vcpkg-release-keys\artifact-private.json `
  --request-verify-key C:\secure\vcpkg-release-keys\request-signing-public.json `
  --output C:\sdk\vcpkg-windows-static.zip
```

Omit `--run` to use the newest successful, unexpired SDK artifact for the
requested platform. For an exact reviewed build, add
`--run RUN_ID --attempt ATTEMPT --builder-sha FULL_SHA`. Use `--work-dir` when
the temporary encrypted/decrypted files need to live on another disk. The command
refuses to run under GitHub Actions and refuses to overwrite an existing output.

With `--request-verify-key`, the tool verifies the signed source request in
addition to the canonical builder workflow/run, GitHub artifact SHA256, encrypted
context, decrypted manifest, SDK digest and archive layout. Without that optional
public verification key, it still checks transport/envelope/manifest integrity but
does not independently authenticate which source request selected the build.
Neither mode authorizes publication; `vcpkg-bin` keeps its independent checks.

## Operational limits

Initial release profile is x64, Release-only. Each compressed SDK is capped at
1900 MiB. Archives reject symlinks, special files, C/C++ implementation source
files, debug trees and symbols; a legitimate package that needs an exception
must be reviewed rather than bypassing the validator. Required public headers,
templates, CMake files and licenses are retained. Static Linux package linkage
does not mean a universally static GUI application without system libraries.

Rerun ALL builder jobs, not only failed jobs: encrypted inputs bind to the exact
attempt. Signed requests expire after 48 hours. Reusing a published tag with
different hashes fails instead of overwriting. After rotating keys or changing
the approved builder revision, drain outstanding runs before enabling new ones.
The initial implementation accepts one active keyset/policy revision; retain old
private backups for offline diagnostics. Rotating salts does not compensate for
a compromised recipient private key.

Secrets and repository settings cannot be provisioned by a Git-only connection.
The local installer performs the authorized secret writes; the operator reviews
branch/tag protection, workflow access and the remaining settings in GitHub.
