# Static multimedia 0.5.2 validation

The 0.5.2 source plans request full GPL FFmpeg 9.0.2#1 and FreeRDP
3.32.2#1 on both platforms, with the qualified CEF recipes/checkpoints and
unchanged triplets. The previous successful 0.5.1 package caches remain
authenticated under their original producer/image context.

## Completed local Linux checks

- Fresh install-root builds reused compatible cached packages.
- All seven exported FFmpeg/FreeRDP CLI executables have neither an ELF
  interpreter nor DT_NEEDED entries. H.264 encode/decode and ffprobe passed.
- An independent CMake consumer of the raw exported SDK found exact versions,
  linked all FFmpeg components and FreeRDP client/server/proxy/shadow, and
  passed codec/filter/runtime checks. Its only dynamic dependencies were
  glibc/libm and the ELF loader, not shared third-party or C++ runtimes.
- All 61 installed FreeRDP channel objects matched their external receipt
  after export; the 16 media-provider archives matched exact package owners.

## Collision resource budget

A read-only preflight against the previously available CEF SDK found 10,149
media collisions after OpenSSL/GCC/atomic-domain precedence, exceeding the
old 8192-symbol budget. Per-archive counts (overlaps are possible):

| Provider | Candidates |
| --- | ---: |
| avcodec / avformat / avutil | 470 / 392 / 674 |
| AOM / dav1d / VPX | 2293 / 2126 / 1700 |
| Opus / WebP | 424 / 509 |
| OpenJPEG / Snappy / libxml2 | 257 / 65 / 1239 |

Sorted candidate-list SHA-256:
`e77fb26e4bf14596c36b951cd4f63657ad41fb36061967a89380d34348e3222e`.
This is diagnostic evidence against a **previous** SDK, not a release receipt
or a symbol allowlist. The bounded maximum is now 16,384. Native tests exercise
more than 8192 definitions, confirm fail-before-mutation under the old bound,
verify complete rewriting and independent provider hashes, link/run both
providers, and confirm the verification path enforces the bound too.

Current native release builds must still derive their exact collisions from
the installed archives, bind all owners/bytes, rewrite only CEF definitions
and references, and pass final relocation/runtime/independent publisher gates.
No admission hash, undefined-symbol exemption or dynamic-library allowlist is
relaxed. CI success alone is not native Windows SDK qualification or evidence
that 0.5.2 has been published.
