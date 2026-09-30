# Offline wheelhouse

This directory is populated by `.github/workflows/vendor-offline-wheels.yml`.

The committed `.whl` files are the official PyPI binary distributions needed to run Tink 1.16.1 on the repository's supported offline hosts:

- CPython 3.12 or 3.13
- Linux x86-64 (glibc 2.28+)
- Windows x64

Every wheel filename and SHA-256 digest is checked by `tools/verify_wheelhouse.py` and must also appear in `requirements.lock`. Do not replace a wheel manually, add an sdist, or weaken `--require-hashes` / `--no-index`.

Private keysets never belong in this directory or anywhere in this repository.
