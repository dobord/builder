# Builder agent notes

## Encrypted CI diagnostics

Builder Actions intentionally keep compiler/runtime diagnostics private. Use public job status and non-sensitive summary artifacts first. Decrypt encrypted diagnostics only when the public evidence is insufficient to identify an exact failure.

### One-time setup

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
- Never commit decrypted logs or derived plaintext diagnostics. Keep them under `/tmp` or another disposable local directory.
- Do not weaken envelope/context/recipient validation to make a decryption succeed.
- Use the minimum diagnostic content needed to identify the failure. Public summaries should contain bounded failure identity whenever possible.
- Do not advance a CEF resumable lock from a failed run unless the run produced a checkpoint explicitly accepted by the strict checkpoint contract.
- Keep the combined CEF lock closed until engine compilation is complete and browser/renderer runtime verification has succeeded.
- Preserve the static FreeRDP contract and `WITH_FFMPEG=ON` while working on CEF qualification.
