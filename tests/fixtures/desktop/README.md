# Public desktop prerequisite fixtures

`source-prerequisites.json.zlib` is zlib-compressed UTF-8 JSON containing only
public source (never CI diagnostics, checkpoints or keys):

- Chromium `79460ebecaa5625e57a5fb679a735659e73dc687`, `ui/gtk/gtk_ui.cc`.
- WebRTC `6f37672d358475cd17544121a12494da454d85fb`,
  `modules/desktop_capture/BUILD.gn` (the revision pinned by that Chromium DEPS).
- The GTK-file portion of CEF
  `708dc140cbc3286826a8abef89dc23a44ff9ea72`'s
  `patch/patches/linux_gtk_theme_3610.patch` (full patch Git blob
  `760b75dd8f263dce36505f981052a92904745d2e`). Unrelated Wayland/X11 hunks are not
  part of this fixture.

The tests validate the compressed digest, full source digests and extracted
patch digest, replay the patch with `git apply` as an independent oracle, and
require CEF GTK output blob `4e7f63878bfa1558167db2e91ad08394b3bd57bb` before
applying the strict GDK/Cairo policy. The complete five-file installer is tested,
including rejection-before-write and unchanged mtimes on repeat.

Stock Chromium was the wrong *workspace* baseline in run 73. It remains the
correct immutable `git show` input. Accepting a new hash while rebuilding from
stock would erase CEF's feature include and theme-notification guards. The fix
composes both changes and admits neither stock-only nor partial prerequisites.

Copyright headers are retained. Chromium uses the BSD license in
`../x11/LICENSE`; WebRTC and CEF notices are in `LICENSES.txt`.
These fixtures and tests confer no CEF runtime or SDK qualification.
