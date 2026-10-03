# Pinned public Xlib source fixture

`pinned-sources.zip.part0` through `.part2` concatenate to a ZIP containing only public Chromium sources at
`79460ebecaa5625e57a5fb679a735659e73dc687`: the Xlib support translation unit,
its three headers, its BUILD.gn, and the library-loader generator/template.
Original copyright notices are retained; see LICENSE.

The test concatenates exactly three numbered parts and checks the complete ZIP
SHA-256 before reading it; incomplete or altered fixtures are rejected. It runs the real generator in
both modes and compiles the entire modified Xlib translation unit at -O0 with
warnings as errors. Only unrelated base utilities are replaced with disposable
scaffolding. The test links and runs a disposable static Xlib provider and
requires a failed link without that provider. This is NOT CEF qualification.

Sources were fetched over HTTPS at exact revisions by the builder's public-only
local-diagnostic-tools workflow, run 35891674601. No CI diagnostics, keys or
private inputs are included in this fixture.
