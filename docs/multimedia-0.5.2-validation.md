# Static multimedia 0.5.2 validation

The 0.5.2 source plans request full GPL FFmpeg 9.0.2#3 and FreeRDP
3.32.2#3 on both platforms, with the qualified CEF recipes/checkpoints and
unchanged triplets. The previous successful 0.5.1 package caches remain
authenticated under their original producer/image context.
Exact package-only continuation artifacts additionally preserve completed
dependencies from candidates; they do not admit failed SDKs or engine proofs.
Linux image `20261018.339.1` is admitted only with the unchanged critical host
fingerprint and exact checkpoint identity beyond the reviewed image field.
Windows transports the same seven pinned XZ documentation companions as Linux
and approves only their five C examples. FFmpeg and XZ source reviews remain
separate, with whole-source inventory before ZIP, ownership/hash checks after
relocation, and independent publisher comparison against its own source pins.

## Completed local Linux checks

- Fresh install-root builds reused compatible cached packages.
- All seven exported FFmpeg/FreeRDP CLI executables have neither an ELF
  interpreter nor DT_NEEDED entries. H.264 encode/decode and ffprobe passed.
- An independent CMake consumer of the raw exported SDK found exact versions,
  linked all FFmpeg components and FreeRDP client/server/proxy/shadow, and
  passed codec/filter/runtime checks. Its only dynamic dependencies were
  glibc/libm and the ELF loader, not shared third-party or C++ runtimes.
- All 61 installed FreeRDP channel objects matched their external receipt
  after export; the initial 16 media-provider archives matched exact package owners.
  A follow-up binds iLBC and all four additional WebP archives as well (21 total),
  including the mux/SharpYUV items explicitly present in FFmpeg's static closure.

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
Including iLBC and the four WebP companions yields 10,334 unique candidates
(iLBC: 100, mux: 57, SharpYUV: 16, demux: 12, decoder: 278; decoder overlaps
the main WebP archive). The complete sorted-list SHA-256 is
`4de2228dcf859d26d197eaf3c88da3865c3fe41abb130b7bbdd911f1ae60d605`.
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
