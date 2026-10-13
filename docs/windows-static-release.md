# Windows-only static SDK release

The signed version-2 request selects `platforms: ["windows"]` and runs
`build-windows-release.yml`. Independent publication accepts only that exact
successful workflow attempt, its signed Windows scope and its final SDK proof.

`v0.2.5-windows` selects the exact READY source checkpoint from run `38181326135`,
attempt 1. `ci/cef-windows-release-lock.json` binds the original producer revision,
artifact and summary digests and repaired build key. The existing native
checkpoint codec, host/workspace identity, envelope and source-repair checks are
retained. The qualification checkpoint is not a release SDK.
The recipe child reconstructs the original producer ref and reviewed logical
image; the publication workflow still authenticates the new main-based run.
An explicit retry may run the source requester on `main`: signed request version
3 binds both the requester revision and the immutable Windows source-tag revision.
Preparation independently requires both revisions in approved source-main history,
the canonical Windows requester workflow and the exact unmoved tag.

The repair binding is part of the vcpkg overlay before ABI computation and is
installed as `share/cef-static/windows-qualified-engine.json`. Publication checks
that file against the independently reconstructed binding. The final relocated
combined consumer must pass the existing Windows browser/renderer module audit
three times with the build, installed and engine workspaces hidden.

Assets are the Windows static-release SDK ZIP, `release-manifest.json` and
`SHA256SUMS` under the separate `v0.2.5-windows` release in private `vcpkg-bin`.
Only encrypted source, package-cache, SDK and diagnostic files leave builder jobs.
