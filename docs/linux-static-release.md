# Linux-only static SDK release

Linux releases run through `dobord/builder` and publish directly to
`dobord/vcpkg-bin`. They do not wait for or start a Windows build.

## Pipeline

1. `dobord/vcpkg/.github/workflows/release-request.yml` sends a signed version-2
   request containing `platforms: ["linux"]` from an immutable `vX.Y.Z` tag.
2. `builder/.github/workflows/build-linux-release.yml` authenticates the request,
   fetches the pinned source revisions, and builds only
   `x64-linux-static-release`. Its jobs are `prepare` and `linux`; there is no
   platform matrix or Windows runner.
3. For a CEF release, the strict source-built profile remains required. The SDK
   retains reviewed native runtime isolation, source/header aliases and installed
   FreeRDP objects. A relocated C API consumer and the actual canonical C++/RDP
   consumer must both pass before `sdk_ready` can be set.
4. The C++ lifecycle test connects a local RDP client, waits for a stable CEF
   renderer, verifies OS-only imports and loaded modules, and requires clean
   proxy/helper shutdown. Static FreeRDP keeps `WITH_FFMPEG=ON`.
5. `request-publication.yml` independently verifies the successful Linux build
   attempt, the signed platform selection, the SDK and runtime evidence. It
   publishes exactly the Linux SDK and its two metadata assets to `vcpkg-bin`.

Assets for tag `vX.Y.Z`:

- `vcpkg-vX.Y.Z-linux-x64-static-release.zip`
- `release-manifest.json`
- `SHA256SUMS`

There is no Windows asset requirement for this workflow. Legacy version-1
requests still belong to the separate two-platform `build-release.yml` path;
a request cannot silently change platform scope between build and publication.

## Source revisions and execution

The CEF client bridge and the lfc-ui subprocess/runtime fixes must be included
in the revisions pinned by the source release plan and matching port `REF`s.
The prepared source plan pins CEF recipe
`5d427cb2d29cd14fbdb3d7fbccbf3822e3b03896` and lfc-ui
`63b456abf22250932df41a55797ed912d1b5b662`; the lfc-ui port uses that same `REF`
at `0.3.0#17`. The Linux canonical-example review binds both the fixed proxy
and the updated port installation policy. An uncommitted working tree is not
a CI input.

The existing `BUILDER_COMMIT_SHA`, `RELEASE_ENABLED`, `PUBLISH_ENABLED`, tokens and
transport keys remain the deployment configuration. `CEF_STATIC_LINUX_RUNNER_LABELS`
selects the Linux runner with capacity for the complete source-built graph; the
native capacity and host checks remain mandatory.

The ordinary `ubuntu-24.04` runner first removes the unused Android, .NET and
GHC installations, using the same capacity recovery as the incremental engine
workflow. This step is limited to GitHub-hosted runners. The source worker still
requires at least 80 GiB free after recovery; it never lowers that threshold.

The Linux source worker applies the reviewed native-link, static GTK/NSS and
Dawn-header profile before compiling. Accepted continuation checkpoints retain
the exact original or native-link recipe fingerprint. Before vcpkg install, the
qualified exporter patch and frozen-dependency replay are ABI-tracked inputs;
installed dependency ownership and isolated platform bytes are rechecked before
packaging. These are the same contracts used by the native engine qualification.

The final Linux consumers use GCC 14 and the independently checked LLD 18.
Native Chromium objects may contain CREL relocations, which LLD 18 does not
apply. Keep the reviewed CREL-to-RELA conversion in the installed CEF isolation
step before export: a successful link alone does not prove startup constructors
or runtime correctness. The converter compares every logical relocation and
object payload before accepting the derivative; the original engine checkpoint
is not modified.

Trigger a new immutable source tag or dispatch the source request workflow using
that exact tag. A clean unfinished engine slice uploads its accepted checkpoint
and completed package cache for continuation, but fails SDK readiness and does
not cause publication. Checkpoints and package-cache artifacts have 90-day
retention in the Linux workflow. A failed or incomplete run never publishes an
SDK. The combined qualification lock is not opened by this workflow setup.

The workflow-reader correction retains the exact accepted Linux continuation
from run `37145188245`, attempt `1`, producer
`35596572fd466fdec9d463c28559a3196e9d4f74`. Both artifact IDs and GitHub digests
are closed review inputs in `cef_cache.LINUX_CONTINUATION`. This run completed
its compilation slice and uploaded a checkpoint; SDK readiness alone stopped
publication. Restoration authenticates its original producer context and the
unchanged native recipe/platform contract. Newly persisted caches use the new
producer's own identity and key. No ciphertext, checkpoint identity or context
is rewritten, and this exception does not admit other old producers.

Run `37189898552/1` completed engine compilation and produced an accepted
checkpoint before SDK installation stopped at its mandatory runtime smoke.
`cef_cache.LINUX_RUNTIME_CONTINUATION` binds that checkpoint and package cache
to their exact IDs/digests and original producer context for requalification
with the complete static X11/unwind profile. This is not runtime qualification
or SDK publication authorization. The source and installed-port smokes keep
strict runtime checks and collect bounded milestones privately.

Final frozen replay uses a fresh `installed/` root. The completed preflight
installation is retained as `platform-installed-before-replay/`, and is hidden
alongside the final producer roots during consumer verification. Classic vcpkg
otherwise skips already-installed dependencies and never invokes their replay
hooks. Run `37201859932/1` passed the engine smoke and installed the full graph
before the ownership check rejected the reused root; its exact accepted
checkpoint/cache context is retained in `LINUX_INSTALL_CONTINUATION` for this
correction. Ownership and SDK readiness requirements are unchanged.

Package `.list` inventories use a dedicated metadata reader: empty meta-port
inventories are valid, each listing is bounded to 8 MiB, and existing 32 MiB
aggregate ownership budgets remain mandatory. Source/example files keep their
separate non-empty 1 MiB policy. Run `37209361089/1` completed frozen replay and
runtime checks before the shared source reader rejected ownership metadata;
`LINUX_INVENTORY_CONTINUATION` retains only its exact accepted checkpoint/cache
for this correction, under the unchanged original authenticated context.

The relocated combined C API consumer uses `cef_combined_smoke.prepare` to
validate the exact original sources and fix only CMake's semicolon/list marker
counting in an isolated copy. The immutable registry, recipe and SDK are not
edited. `LINUX_SMOKE_CONTINUATION` retains the exact accepted producer from
`37220574288/1`, which completed SDK packaging before the legacy marker guard
stopped consumer configure. The marker remains uniquely required and all
runtime/component checks remain in place.
