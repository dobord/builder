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
- `tools/tink_offline.py`: offline launcher that bootstraps only from the committed wheelhouse.
- `tools/verify_wheelhouse.py`: exact filename/SHA-256 verifier for every vendored wheel.
- `vendor/wheels/`: official binary wheels for Tink 1.16.1 and its pinned runtime dependencies.
- `.github/workflows/vendor-offline-wheels.yml`: regenerates the committed wheelhouse from exact lock hashes.
- `.github/workflows/ci.yml`: PUBLIC synthetic tests only; disposable PUBLIC test keys protect no private data.
- `.github/workflows/build-release.yml`: real encrypted release build, disabled until configured.
- `.github/workflows/request-publication.yml`: dispatch publisher after completed successful build.

All actions are pinned by full SHA; crypto dependencies and CMake are wheel-only
and SHA256 pinned. Source and recipient repositories are fixed by immutable IDs.
No `pull_request_target`, no inherited release secrets, no shared private cache.
Only encrypted `.enc` files leave release jobs in this public repository. Never
upload plaintext diagnostics, source archives, credentials or private SDKs here.

## Installation

Use CPython 3.12 or 3.13 on Windows x64 or Linux x86-64 and authenticated GitHub
CLI with administrator access to the three repositories. For normal online setup
on the trusted operator machine:

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

## Offline Tink 1.16.1 diagnostic decryption

The official Tink Python package is a library, not a standalone upstream CLI.
For offline operation this repository commits the official PyPI binary wheels
needed for its supported hosts and provides a small launcher around the existing
`secure_release.decrypt_local` command. The launcher does not reimplement any
cryptography.

Verify the bundle and the exact Tink version:

```sh
python tools/verify_wheelhouse.py
python tools/tink_offline.py --version
```

On first use, `tools/tink_offline.py` creates `.offline-tink/` and installs
only from `vendor/wheels/` using all of:

```text
--no-index
--require-hashes
--only-binary=:all:
```

There is no package-index/network fallback. The wheelhouse covers CPython
3.12/3.13 on Linux x86-64 (glibc 2.28+) and Windows x64. The lock contains only
the accepted hashes for those targets.

Decrypt an encrypted compiler diagnostic locally:

```sh
python tools/tink_offline.py \
  --ciphertext /private/path/diagnostic.enc \
  --private-key /private/path/output-private.json \
  --output /private/path/diagnostic.log \
  --run BUILD_RUN_ID \
  --attempt BUILD_ATTEMPT \
  --builder-sha FULL_40_HEX_BUILDER_SHA \
  --platform linux
```

Use `--platform windows` for a Windows diagnostic. Run/attempt/builder SHA are
deliberately explicit: the decryptor reconstructs the expected authenticated
context instead of trusting context copied from an untrusted ciphertext header.

The private key file is the decoded Tink JSON keyset, not the base64 transport
text. If your backup is base64-encoded, decode it once into a mode-restricted
file outside every Git worktree. Feed secret material through stdin or a protected
file; do not put the key in shell command arguments, environment variables,
README examples, issues, Actions logs or repository files.

The provided output private key is intentionally not committed. Existing ignore
rules cover common private-key names, and `.offline-tink/` is also ignored.

## Refreshing the offline wheelhouse

`requirements.lock` is the authority. It pins Tink 1.16.1 and every required
runtime dependency by exact SHA-256. When that lock or the wheel verifier changes,
`.github/workflows/vendor-offline-wheels.yml` downloads binary wheels only,
checks the exact expected filenames and SHA-256 values, and commits
`vendor/wheels/*.whl`. Do not hand-edit or replace vendored wheels.

A supported offline installation is therefore reproducible from a repository
clone alone; internet access is needed only when intentionally refreshing the
committed wheelhouse.

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
