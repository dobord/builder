# Non-executing target archive audit

`python -m secure_release.static_audit --sdk SDK.zip --platform linux --output audit.json`
examines the requested raw-export target prefix. Add `--require-static-archives`
to reject structurally shared or unqualified target libraries. Nothing from the
SDK is executed. Report files must remain encrypted in the public builder.

The scanner reads ordinary GNU/BSD/COFF archive members with bounded sizes.
It distinguishes ELF relocatable objects from ELF images, short COFF import
objects, long COFF `.idata`/`.didat` imports, ordinary COFF and BigObj objects.
Thin/nested archives and unknown members are not accepted as qualified native
objects. LLVM bitcode requires a separate toolchain/link qualification; it is
reported as unqualified, not guessed static. Empty archives alone cannot prove
that an SDK contains target code. Versioned shared-library names and binary
images hidden under other suffixes are reported too.

Scope is target `lib` and `bin`, not host tools. This report does NOT prove absence
of unresolved external dependencies, `dlopen`/LoadLibrary dependencies, safe
sandboxing or correct runtime behavior. Full-profile publication must additionally
require qualified external dependency closure, final executable import/module
checks and the fresh relocated combined consumer. A clean archive report is
never permission to promote an `engine-static` profile as fully static.

References used for the parser:
- https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- https://github.com/llvm/llvm-project/blob/main/llvm/include/llvm/BinaryFormat/COFF.h

Tests include actual compiler-produced ELF archives/shared images on Linux and
MSVC static/import libraries on Windows, plus synthetic truncation, BigObj,
versioned-SO, relocation and malformed-path regressions. A skipped native test
on a different OS does not constitute native platform evidence.
