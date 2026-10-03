#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python="${PYTHON:-python3}"
venv="${BUILDER_LOG_DECRYPTOR_VENV:-$repo_root/.venv-log-decryptor}"

if ! command -v "$python" >/dev/null 2>&1; then
  echo "Python interpreter not found: $python" >&2
  exit 2
fi

if [[ ! -x "$venv/bin/python" ]]; then
  "$python" -m venv "$venv"
fi

"$venv/bin/python" -m pip install   --disable-pip-version-check   --require-hashes   --only-binary=:all:   -r "$repo_root/requirements.lock"

PYTHONPATH="$repo_root" "$venv/bin/python" - <<'PY'
from secure_release import encrypted_logs
from secure_release import crypto
crypto._tink()
assert callable(encrypted_logs.decrypt_archive)
PY

printf 'Builder log decryptor ready: %s\n' "$venv/bin/python"
printf 'Example: %q %q --input ARTIFACT.zip --private-key KEY.private.b64 --output /tmp/builder-logs\n'   "$venv/bin/python" "$repo_root/scripts/decrypt-builder-logs.py"
