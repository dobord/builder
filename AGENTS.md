# Builder agent notes

## Encrypted CI diagnostics

Builder Actions intentionally keep compiler/runtime diagnostics private. Use public job status and non-sensitive summary artifacts first. Decrypt encrypted diagnostics only when the public evidence is insufficient to identify an exact failure.

### Zero-install OpenSSL fallback

For local diagnostic decryption, prefer the OpenSSL reader when OpenSSL 3 is already available. It uses only Python's standard library plus `libcrypto`; it does not install packages, access a package index, or define a second encryption format:

```bash
python3 scripts/decrypt-builder-logs-openssl.py --version
python3 scripts/decrypt-builder-logs-openssl.py \
  --input /path/to/encrypted-logs-artifact.zip \
  --private-key ~/builder-ci-log-key.private.b64 \
  --output /tmp/builder-ci-logs-RUN_ID
```

The OpenSSL reader accepts the existing base64 transport key or decoded Tink JSON key file. It reads the existing `VCPKGSE1` HPKE + `AES256_GCM_HKDF_1MB` format and validates the recipient fingerprint, authenticated context, every streaming tag, archive paths, manifest identity, sizes, and SHA-256 digests before publishing the output directory. If `libcrypto` is not auto-detected, pass `--openssl-library /path/to/libcrypto` or set `BUILDER_OPENSSL_CRYPTO_LIBRARY`.

Tink remains the encryption/reference implementation. If both readers are available, treat any disagreement as a hard failure; never modify ciphertext, context, key metadata, or acceptance policy to make either reader succeed. The OpenSSL reader is for LOCAL diagnostics only and does not authorize publication.

### Tink reference setup

From the repository root:

```bash
./scripts/install-log-decryptor.sh
```

This creates `.venv-log-decryptor/` and installs the hash-pinned packages from `requirements.lock`. Do not install an unpinned replacement Tink package for this workflow.

### Decrypt a downloaded artifact

Keep the private key out of commits, issues, Actions logs, shell tracing, and chat output. Prefer storing it outside the repository and make it owner-readable only:

```bash
chmod 600 ~/builder-ci-log-key.private.b64
.venv-log-decryptor/bin/python scripts/decrypt-builder-logs.py \
  --input /path/to/encrypted-logs-artifact.zip \
  --private-key ~/builder-ci-log-key.private.b64 \
  --output /tmp/builder-ci-logs-RUN_ID
```

The decryptor also accepts a raw `.enc` file. For a ZIP it requires exactly one safe `.enc` member, validates bounded sizes, and delegates authenticated decryption/extraction to `secure_release.encrypted_logs.decrypt_archive`. The output directory must not already exist.

After analysis, delete plaintext diagnostics:

```bash
rm -rf /tmp/builder-ci-logs-RUN_ID
```

### Rules for agents

- Never print, echo, `cat`, upload, commit, or paste the private key. Pass only its filesystem path to the decryptor.
- Prefer the zero-install OpenSSL reader for local diagnostics when OpenSSL 3 is already present; use the Tink reader as the reference/fallback. A disagreement is a hard failure, not a reason to weaken validation.
- Never extend the OpenSSL compatibility reader into an encryption or publication path.
- Never commit decrypted logs or derived plaintext diagnostics. Keep them under `/tmp` or another disposable local directory.
- Do not weaken envelope/context/recipient validation to make a decryption succeed.
- Use the minimum diagnostic content needed to identify the failure. Public summaries should contain bounded failure identity whenever possible.
- Do not advance a CEF resumable lock from a failed run unless the run produced a checkpoint explicitly accepted by the strict checkpoint contract.
- Keep the combined CEF lock closed until engine compilation is complete and browser/renderer runtime verification has succeeded.
- Preserve the static FreeRDP contract and `WITH_FFMPEG=ON` while working on CEF qualification.
## Security boundary

This public repository implements an encrypted release transport. Treat all
private keysets, decrypted diagnostics, private source archives, tokens and
plaintext SDKs as secrets. Never add them to Git, GitHub Actions logs, issues,
pull requests, examples or test fixtures.

The operator's output private key is local-only. Code may accept a path to a
private key file, but must not print key material, copy it into the worktree,
store it in an environment variable, or pass the key contents on a command line.

## Tink dependency policy

Runtime cryptography uses the official Python package `tink==1.16.1`.
`requirements.lock` is authoritative and must remain exact-version and
SHA-256 hash pinned. Do not replace Tink with a reimplementation, an sdist, a
system package or an unpinned dependency.

Supported offline hosts are:

- CPython 3.12 / 3.13
- Linux x86-64 with glibc 2.28+
- Windows x64

The official wheels and pinned runtime dependencies are committed under
`vendor/wheels/`. `tools/verify_wheelhouse.py` defines the exact accepted
filenames and SHA-256 values. Any wheelhouse change must match hashes already
present in `requirements.lock`.

Offline installation must use `--no-index --require-hashes
--only-binary=:all:`. Never add a network fallback.

## Diagnostic decryptor

For an operator asking to decrypt encrypted build logs, use the ready offline
launcher:

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

Use `--platform windows` for Windows logs. The launcher delegates to
`secure_release.decrypt_local`; it must not weaken or bypass the explicit
run/attempt/builder-SHA/platform context check.

`python tools/tink_offline.py --version` must report Tink 1.16.1 after
bootstrapping from the local wheelhouse only.

## Wheelhouse maintenance

`.github/workflows/vendor-offline-wheels.yml` is the only intended online
refresh path. It downloads binary wheels from PyPI using `requirements.lock`,
verifies exact filenames and hashes, then commits `vendor/wheels/*.whl`.

Do not hand-replace wheel binaries. When changing `requirements.lock`, update
`tools/verify_wheelhouse.py` in the same reviewed change and let the workflow
regenerate the wheelhouse.

## Crypto/protocol changes

Preserve the existing envelope, HPKE, Streaming AEAD, context construction,
recipient fingerprint checks, size bounds and atomic-decryption behavior.
Do not trust context copied from a ciphertext header as a substitute for an
operator-supplied expected context.

Decryption is for local diagnostics and is not release authorization.

## Validation

For changes touching the offline tool or lockfile, run:

```sh
python tools/verify_wheelhouse.py
python tools/tink_offline.py --version
python -m unittest discover -s tests -v
```

The first two commands must work without internet once `vendor/wheels/` is
present.
