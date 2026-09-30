# AGENTS.md

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
