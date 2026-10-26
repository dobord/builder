# Offline public compiler-regression inputs

`public-ci-inputs.zip` contains 34 exact **public** Chromium, V8 and PDFium
compiler-regression inputs, plus their upstream BSD/MIT/Apache licenses. It
contains no private project source, compiler logs, SDK payloads or credentials.
Its manifest records each immutable official URL, byte size, SHA-256 and Git blob
ID. Members are keyed by the SHA-256 of their URL, preserving upstream bytes and
copyright notices without checkout line-ending conversion. The top-level archive
digest is pinned in `tests/public_ci_inputs.py`.

This is test data only, never a build-worker source or SDK/checkpoint substitute.
Tests read it without network, extraction or subprocess execution. Existing
individual size, SHA-256 and Git blob checks remain in place. Explicit
`CEF_WINDOWS_*_SOURCE_ROOT` inputs continue to use and validate the selected exact
checkout. Missing, modified, mismatched or unreviewed data fails closed; no test
is skipped and no mutable upstream ref or runtime network fallback is accepted.

## Maintenance

After reviewing changes to the declarative fixture pins, generate a fresh file:

```sh
python tools/vendor_public_ci_inputs.py --output /private/staging/public-ci-inputs.zip
```

The output must not exist and its parent must exist. This non-executing operator
tool parses only fixture constants; it never imports tests. It downloads bounded
files from the exact official GitHub raw URLs, with a bounded same-revision
official Gitiles fallback for transient transport failures. It verifies the
existing pins before constructing a deterministic stored ZIP with fixed metadata.
License files are acquired from the same immutable repositories/revisions and
hashed in the manifest. Inspect the manifest, all pin matches and license notices,
then replace the archive and update its reviewed digest together.

Run `python -m unittest tests.test_public_ci_inputs -v` and the affected native
regressions. The tests check complete pin coverage, licenses, archive integrity,
default-deny URL/size behavior and clean-subprocess operation with network disabled.
Full Linux/Windows hosted security and CEF integration checks remain required.
