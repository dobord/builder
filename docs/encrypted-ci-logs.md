# Encrypted CI logs

Critical native builder jobs can upload a ciphertext-only artifact named
`ШИФРОВАНЫЕ ЛОГИ-<job>-<run>-<attempt>`.

The repository never needs the decryption key. Generate a stable Tink hybrid
keypair locally:

```bash
python -m pip install --disable-pip-version-check --require-hashes --only-binary=:all: -r requirements.lock
python -m secure_release.encrypted_logs keygen --prefix builder-ci-log-key
```

Keep `builder-ci-log-key.private.b64` offline. Configure the contents of
`builder-ci-log-key.public.b64` as the repository secret
`BUILDER_ENCRYPTED_LOGS_PUBLIC_KEY_B64`.

The CI action collects bounded runner-local diagnostic files only, excludes
credential/secret/key-like names and binary build payloads, creates a temporary
compressed tar archive, encrypts it with the existing Tink streaming envelope,
deletes the plaintext archive, and uploads only `*.enc`.

Inspect an artifact without a key:

```bash
python -m secure_release.encrypted_logs inspect --input <artifact.enc>
```

Decrypt locally:

```bash
python -m secure_release.encrypted_logs decrypt \
  --input <artifact.enc> \
  --private-key-file builder-ci-log-key.private.b64 \
  --output-dir decrypted-ci-logs
```

The decrypted directory contains `manifest.json` plus the selected logs with
their root-relative paths. The manifest binds repository, workflow, job, run,
attempt, commit SHA, recipient fingerprint, per-file sizes and SHA-256 hashes.

Do not commit or upload the private key. Rotating the public-key secret requires
retaining the corresponding old private key for older artifacts.
