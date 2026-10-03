# Reviewed HarfBuzz static boundary

The combined #71 comparison found 25 built-only and 43 frozen-only definitions
in `libharfbuzz.a`. Every differing definition was an ELF `WEAK HIDDEN FUNC`
with a C++ mangled name. The 38 installed public headers matched the qualified
platform, and neither difference contained a public `hb_*` entry point. These
observations alone do **not** prove static compatibility: a companion archive
can reference a hidden symbol.

The pinned HarfBuzz 14.2.1 source defines its public C ABI in `.h` declarations
(`src/gen-def.py`, Git blob `be4e68881cb41b711bf4b4f87cc14090b6e28237`). Its
`hb-cplusplus.hh` is an installed convenience API and must not be mistaken for
an internal header. The implementation differences observed in #71 come from
private template bodies in the vector/lazy-loader/sanitizer and OpenType/CFF
implementation, not new C declarations. Different internal emission is not a
reason to change the runtime-qualified archive hash.

The alternate replay path is confined to **this exact** HarfBuzz version,
`core;c-linker;freetype` feature set, qualified archive/header inventory, and
both reviewed difference-set SHA256s. It never generally ignores weak, hidden,
or mangled symbols. It additionally requires:

* Identical public header inventory and bytes, including the C++ wrapper, and
  coverage of every built public C entry point with unchanged ELF attributes.
* No unresolved reference to a built-only definition from other frozen,
  staged companion, or already installed link inputs. An archive providing its
  own matching COMDAT is not an incoming edge into the replaced archive.
* Whole-archive linking of the entire frozen core against only its captured
  static dependency closure. This includes otherwise unreferenced objects;
  missing internal/external definitions cannot hide behind a small smoke.
* Compilation of an address-taking public-C-API probe and a C++ wrapper
  consumer, an OS-only ELF check, and execution of version/buffer/shaping and
  wrapper-lifetime checks. Final SDK/CEF runtime and relocation remain separate
  mandatory gates.

A mismatch or failed proof keeps the original symbol-rejection behavior and
preserves staging archive/header bytes. Failed proof command details remain
only in the runner-local encrypted diagnostic selection. The installed receipt
contains bounded counters and hashes, not diagnostic names or logs. All helper
bytes and the installed consumer-root specification are ABI-tracked.

This is a bounded approval to reuse one authenticated **whole implementation**
behind its checked public boundary, not a general claim of ABI equivalence, an
exception to the OS-only module policy, or proof that independent rebuilds are
byte-reproducible. Any new difference set or feature requires another review.
The full qualification must still pass with real HarfBuzz and downstream
`lfc-ui[freerdp,cef]`; disposable native fixtures are not that qualification.

## Composition with the concurrent #72 implementation

The uploaded patch SHA256 is
`f7d8afb998c17e5d52811539e37bb396c8963d393dca43b92ce1b7526ac5b633`.
Its original base is `58f74edfe660c30797efc4a3e4c7da081e312049`.
By application time, `1adb3657954b0d8f44e05a7fc8291b71d3098afd`
already added the public interface inventory, stricter common ELF metadata,
installed-root hook wiring and receipt validation. Those changes are retained.
The uploaded additional verifier runs as `reviewed_verify` only AFTER the
existing closed-boundary/native proof succeeds, and BEFORE a proof is returned
to the replay hook. Both stages must pass; neither stage is an alternative to
the other. The existing receipt schema and post-install/relocation revalidation
remain unchanged. The combined module is already directly ABI-tracked and its
full digest is checked by the package hook. The source-clock mock correction
is applied unchanged. Both native test sets run before large checkpoint restore.
