"""Prove a closed HarfBuzz C interface before replaying its WHOLE static archive.

Only the pinned 14.2.1 c-linker/core/freetype package is eligible. Hidden weak
C++ functions are not generally optional: matching public headers/API, both
ELF differences, all sibling/frozen/installed archive references and a real
C-linker probe must pass. Every other port keeps the original superset rule.
No archive, symbol or manifest is edited by this module. It returns bounded
proof counts; command diagnostics stay runner-local for encrypted collection.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

INTERFACE = Path(__file__).resolve().parents[1] / 'ci/cef-harfbuzz-interface.json'
INTERFACE_SHA256 = '9c07763e98aab687b18f43f576a1215d870d78d70f8381fb4e0597f97fa1f0ab'
ARCHIVE = 'lib/libharfbuzz.a'
FEATURES = frozenset({'core', 'c-linker', 'freetype'})
# Same OS-only policy as the existing strict native ELF gate.
OS_NEEDED = frozenset({'libc.so.6','libm.so.6','libdl.so.2','libpthread.so.0',
                      'librt.so.1','ld-linux-x86-64.so.2'})
SYMBOL = re.compile(r'[A-Za-z_.$][A-Za-z0-9_.$@]*\Z')


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def regular(path: Path) -> None:
    require(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)),
            'Redirected or missing HarfBuzz boundary input')


def run(args: list[str], *, timeout: int = 120, cwd: Path | None = None) -> str:
    result = subprocess.run(list(map(str,args)), cwd=cwd, capture_output=True, text=True,
                            timeout=timeout, env=dict(os.environ, LC_ALL='C'))
    require(result.returncode == 0 and len(result.stdout) <= 128 * 1024**2,
            'HarfBuzz boundary native command failed')
    return result.stdout


def verified_metadata_alias(path: Path, root: Path, inventory: dict) -> bool:
    """Recognize only the pinned libxcrypt pkg-config alias, never a link input.

    libxcrypt 4.5.2 Makefile.am installs libcrypt.pc -> libxcrypt.pc. The
    qualified manifest captures both as identical regular metadata. Installed
    pkg-config prefix text may be relocated; do not overwrite or reinterpret it.
    All object/archive/shared-library and directory links still fail closed.
    """
    alias = 'lib/pkgconfig/libcrypt.pc'
    target_name = 'lib/pkgconfig/libxcrypt.pc'
    if path != root / alias or not path.is_symlink():
        return False
    records = inventory.get('files', {})
    a, b = records.get(alias), records.get(target_name)
    require(isinstance(a, dict) and a == b and set(a) == {'size', 'sha256'}
            and type(a['size']) is int and a['size'] > 0
            and isinstance(a['sha256'], str)
            and re.fullmatch(r'[0-9a-f]{64}', a['sha256']) is not None,
            'Unbound libxcrypt metadata alias')
    require(os.readlink(path) == 'libxcrypt.pc', 'Redirected libxcrypt metadata alias')
    target = root / target_name
    regular(target)  # Includes every parent; reject chains and redirected dirs.
    require(0 < target.stat().st_size <= 65536, 'Invalid libxcrypt metadata target')
    data = target.read_bytes()
    require(b'\0' not in data and not data.startswith((b'!<arch>', b'!<thin>', b'\x7fELF')),
            'libxcrypt metadata alias is not pkg-config text')
    require(any(line.startswith(b'Name:') for line in data.splitlines())
            and any(line.startswith(b'Libs:') for line in data.splitlines()),
            'Incomplete libxcrypt pkg-config alias target')
    return True


def symbols(archive: Path) -> tuple[dict[str, set[tuple[str,str,str]]], set[str]]:
    """Read all ELF definitions and references, not nm's lossy visibility view."""
    regular(archive)
    with archive.open('rb') as f:
        require(f.read(8) == b'!<arch>\n', 'HarfBuzz proof needs regular ELF archives')
    definitions: dict[str,set[tuple[str,str,str]]] = {}
    undefined = set()
    text = run(['readelf','--wide','--symbols',str(archive)])
    parsed = 0
    for line in text.splitlines():
        f = line.split()
        if not (len(f) == 8 and f[0].endswith(':') and f[0][:-1].isdigit()):
            continue
        kind, binding, visibility, section, name = f[3:8]
        if binding not in {'GLOBAL','WEAK','UNIQUE'}:
            continue
        require(SYMBOL.fullmatch(name) is not None, 'Unknown HarfBuzz symbol spelling')
        parsed += 1
        if section == 'UND':
            undefined.add(name)
        else:
            definitions.setdefault(name,set()).add((kind,binding,visibility))
    require(parsed > 0 and definitions, 'Empty or unsupported HarfBuzz ELF inventory')
    return definitions, undefined


def interface(package: Path, prefix: Path, inventory: dict) -> set[str]:
    regular(INTERFACE)
    require(digest(INTERFACE) == INTERFACE_SHA256, 'Public HarfBuzz interface policy changed')
    policy = json.loads(INTERFACE.read_bytes())
    known = set(policy['headers']) | {'hb-features.h'}
    expected = {'include/harfbuzz/'+name for name in known}
    captured = {n for n in inventory['files'] if n.startswith('include/harfbuzz/')}
    require(expected == captured, 'Frozen HarfBuzz header boundary differs from reviewed source')
    actual = {p.name for p in (package/'include/harfbuzz').iterdir()}
    require(actual == known, 'Staged HarfBuzz exports unknown or missing public headers')
    for name in sorted(known):
        rel = 'include/harfbuzz/'+name
        for root in (package,prefix):
            path = root/rel; regular(path)
            require(digest(path) == inventory['files'][rel]['sha256'],
                    'HarfBuzz public header no longer matches qualified engine')
            if name != 'hb-features.h':
                require(digest(path) == policy['headers'][name],
                        'HarfBuzz public header differs from pinned 14.2.1 source')
    # gen-def.py in pinned HarfBuzz uses this exact declaration spelling.
    # Do not infer optional API availability solely from declarations: compare
    # actual definitions below, including any new non-declared public symbol.
    text = '\n'.join((package/'include/harfbuzz'/n).read_text() for n in policy['core_headers']
                     if n.endswith('.h'))
    api = set(re.findall(r'^hb_\w+(?= \()',text,re.M))
    require(len(api) > 400 and {'hb_shape','hb_buffer_create','hb_ft_font_create'} <= api,
            'Incomplete HarfBuzz public C declarations')
    return api


def closed_difference(built: Path, frozen: Path, declared: set[str],
                      others: list[Path]) -> tuple[set[str],dict]:
    """Lower-level proof; callers MUST establish the exact source/feature scope."""
    b, _ = symbols(built); f, fu = symbols(frozen)
    bn, fn = set(b), set(f)
    b_only, f_only = bn-fn, fn-bn
    require(b_only, 'HarfBuzz boundary proof is only for an actual symbol difference')
    delta = b_only | f_only
    for name in delta:
        # C entry points, data/TLS/vtables, non-weak and visible symbols cannot
        # disappear. Public C++ convenience wrappers use hb:: / std:: namespaces.
        metadata = (b if name in b_only else f)[name]
        require(name.startswith('_Z') and metadata == {('FUNC','WEAK','HIDDEN')}
                and name not in declared, 'HarfBuzz difference is not a private function boundary')
    demangled = subprocess.run(['c++filt'], input='\n'.join(sorted(delta))+'\n',
                               capture_output=True,text=True,timeout=30)
    require(demangled.returncode == 0, 'Cannot classify HarfBuzz private definitions')
    names = demangled.stdout.splitlines()
    require(len(names) == len(delta) and all('::' in n and not n.startswith('_Z')
            and 'hb::' not in n and 'std::' not in n for n in names),
            'HarfBuzz difference overlaps public C++ wrappers or unclassified symbols')
    c_b = {n for n in bn if n.startswith('hb_')}
    c_f = {n for n in fn if n.startswith('hb_')}
    require(c_b == c_f and c_b <= declared and c_b,
            'HarfBuzz C API definitions changed')
    for name in c_b:
        require(b[name] == f[name] == {('FUNC','GLOBAL','DEFAULT')},
                'HarfBuzz C entry-point binding changed')
    # Differences in common non-public records are not silently accepted either.
    require(all(b[n] == f[n] for n in bn & fn), 'HarfBuzz common ELF binding changed')
    # Whole-archive replacement drops the rebuilt objects AND their references.
    # References from the replacement or ANY surviving archive are different:
    # they must not depend on a definition found only in the removed archive.
    require(not (fu & b_only), 'Frozen HarfBuzz has unresolved removed internals')
    seen = set()
    for archive in others:
        if archive == built or archive in seen:
            continue
        seen.add(archive)
        owned, undefined = symbols(archive)
        require(not ((undefined - set(owned)) & b_only),
                'Another archive requires a removed HarfBuzz internal')
        require(all(owned[n] == b[n] for n in b_only & set(owned)),
                'A surviving archive changes a private HarfBuzz binding')
    return c_b, {'public_functions':len(c_b),'private_built_only':len(b_only),
                 'private_frozen_only':len(f_only),'reference_archives':len(seen)}


def link_probe(prefix: Path, inventory: dict, api: set[str], output: Path) -> None:
    """Every enabled public function is a live link root in a real C executable.

    No untyped function is called. A separate TU uses the exact installed hb.h
    declarations for real UTF-8 buffer/shape lifecycle calls. Link against only
    qualified frozen static archives, never host third-party -l aliases.
    """
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    refs = output/'api.c'
    refs.write_text('#include <hb.h>\n#include <hb-ot.h>\n#include <hb-aat.h>\n#include <hb-ft.h>\n' +
        'void (*volatile const proof_api[])(void) = {\n'+
        ''.join('  (void (*)(void))&'+n+',\n' for n in sorted(api))+'};\n'+
        'int proof_roots(void) { for(unsigned i=0;i<sizeof(proof_api)/sizeof(*proof_api);i++)'
        ' if(!proof_api[i])return 1; return 0;}\n')
    main = output/'main.c'
    main.write_text('#include <hb.h>\nextern int proof_roots(void);\n'
        'int main(void){if(proof_roots())return 1;'
        'hb_buffer_t*b=hb_buffer_create(); if(!b)return 2;'
        'hb_buffer_add_utf8(b,"abc",-1,0,-1);hb_buffer_guess_segment_properties(b);'
        'hb_font_t*f=hb_font_create(hb_face_get_empty());hb_shape(f,b,0,0);'
        'unsigned n=0;hb_glyph_info_t*g=hb_buffer_get_glyph_infos(b,&n);'
        'int bad=(!g||n!=3);hb_font_destroy(f);hb_buffer_destroy(b);return bad;}\n')
    paths = [prefix/n for n in inventory['archive_objects']]
    executable = output/'harfbuzz-boundary'
    command = ['cc','-O0','-static-libgcc','-I'+str(prefix/'include/harfbuzz'),
               '-I'+str(prefix/'include/freetype2'),str(refs),str(main),
               '-Wl,--no-gc-sections','-Wl,--start-group',*map(str,paths),'-Wl,--end-group',
               '-lm','-ldl','-lrt','-pthread','-o',str(executable)]
    result = subprocess.run(command,capture_output=True,text=True,timeout=240)
    (output/'link.log').write_text(result.stdout+result.stderr)
    require(result.returncode == 0, 'Qualified HarfBuzz public C-link proof failed')
    needed = re.findall(r'\(NEEDED\).*?Shared library:\s*\[([^\]]+)\]',
                        run(['readelf','-d',str(executable)]))
    require(needed and set(needed) <= OS_NEEDED,'HarfBuzz C-link probe acquired a non-OS library')
    result = subprocess.run([str(executable)],capture_output=True,text=True,timeout=30)
    (output/'run.log').write_text(result.stdout+result.stderr)
    require(result.returncode == 0,'Qualified HarfBuzz buffer/shape lifecycle proof failed')


def verify(*, package: Path, prefix: Path, inventory: dict, version: str,
           features: str, installed: Path, output: Path) -> dict:
    require(version == '14.2.1' and set(features.split(';')) == FEATURES,
            'Unreviewed HarfBuzz version or feature closure')
    require(package.name == 'harfbuzz_x64-linux-static-release', 'Wrong HarfBuzz owner')
    declared = interface(package,prefix,inventory)
    built,frozen=package/ARCHIVE,prefix/ARCHIVE
    for rel,record in inventory['files'].items():
        path=prefix/rel;regular(path)
        require(path.stat().st_size==record['size'] and digest(path)==record['sha256'],
                'Qualified HarfBuzz dependency bytes changed')
    require(installed.is_dir() and not any(p.is_symlink() for p in (installed,*installed.parents)),
            'Missing or redirected consumer-prefix evidence')
    others = [prefix/n for n in inventory['archive_objects']]
    for root in (package/'lib',installed/'lib'):
        for path in root.rglob('*'):
            if path.is_symlink():
                require(verified_metadata_alias(path, root.parent, inventory),
                        'Redirected surviving HarfBuzz consumer: ' + path.relative_to(root).as_posix())
                continue  # Validated metadata only; not an ELF reference input.
            if path.is_file() and path.suffix in {'.a','.o'}:
                require(path.suffix == '.a','Unreviewed loose object in HarfBuzz consumers')
                others.append(path)
    api,proof = closed_difference(built,frozen,declared,others)
    require({'hb_shape','hb_buffer_create','hb_ft_font_create',
             'hb_ft_face_create','hb_version_string'} <= api,
            'HarfBuzz declared core/FreeType feature API is missing')
    link_probe(prefix,inventory,api,output)
    # The user-supplied patch adds the exact observed delta and whole-core/C++
    # proof. Require it IN ADDITION to the existing interface and receipt gates.
    reviewed_verify(
        {"prefix": str(prefix), "installed": str(installed)}, inventory,
        package, "harfbuzz", features, version, ARCHIVE,
        set(symbols(built)[0]), set(symbols(frozen)[0]),
        diagnostics=output / "reviewed-whole-boundary",
    )
    return {'schema':1,'kind':'harfbuzz-14.2.1-closed-c-boundary',
            **proof,'public_link_verified':True,'runtime_verified':False,
            'built_sha256':digest(built),'frozen_sha256':digest(frozen),
            'interface_sha256':INTERFACE_SHA256,'policy_sha256':digest(Path(__file__))}


# Additional whole-archive/C++ proof reconciled from the supplied patch.
"""Prove the reviewed HarfBuzz private-template boundary, not a visibility waiver.

Only the exact 14.2.1 core/freetype C-linker profile and the reviewed two symbol
set differences qualify. Hidden/weak/C++ alone never authorizes substitution.
Require identical installed public headers (including C++ convenience wrappers),
all public C entry points, no incoming reference from any current consumer, a
complete static re-link of the frozen core, and a native C/C++ API execution.
The parent replay still installs the original authenticated archive byte-for-byte.
No diagnostic symbol names are emitted or retained in the installed receipt.
"""

import hashlib
import contextvars
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

# Reviewed against the SHA512-pinned 14.2.1 source acquired by the unchanged port.
# src/gen-def.py derives the C ABI from declarations; src/check-symbols.py rejects
# internal names in the shared ABI. Static archives additionally need the incoming
# reference checks below: hidden visibility alone does NOT prevent static use.
REVIEW = {
    "archive_sha256": "e9eb491b3f73d575a6c7e0f10089c29439ecc973317e8312d202459032ea9a65",
    "headers_sha256": "361c5a5ee4279aaee47eee2c1a33b0d9fb46aad627dd0ca85b815141cd1cc882",
    "built_only_sha256": "e921ec8012e6b522be5e16a4dc0e14e30783ac6a4e5d12721750e215df35c63d",
    "frozen_only_sha256": "8da3c4bbcd0817f254429d4e557ffe995b9974df7a8376c1c10b184d62e62cb6",
    "built_only_count": 25, "frozen_only_count": 43,
}
PROFILE = "harfbuzz-14.2.1-c-linker-core-freetype-boundary-v1"
_TRACE = contextvars.ContextVar("harfbuzz_boundary_trace", default=None)
API = re.compile(r"^hb_\w+(?= \()", re.M)
SYMBOL = re.compile(r"[A-Za-z_.$][A-Za-z0-9_.$@]*\Z")


def reviewed_require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError("HarfBuzz boundary: " + message)


def digest_names(names: set[str]) -> str:
    return hashlib.sha256(("\n".join(sorted(names)) + "\n").encode()).hexdigest()


def command(args: list, *, cwd: Path | None = None, timeout: int = 120) -> str:
    result = subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True,
                            text=True, timeout=timeout, env=dict(os.environ, LC_ALL="C"))
    if result.returncode or len(result.stdout) > 128 * 1024**2:
        trace = _TRACE.get()
        if trace is not None:
            trace.append({"program": Path(str(args[0])).name,
                          "exit_code": result.returncode,
                          "stdout_tail": result.stdout[-256 * 1024:],
                          "stderr_tail": result.stderr[-256 * 1024:]})
        raise ValueError("HarfBuzz boundary: native proof command failed")
    return result.stdout


def undefined(path: Path) -> set[str]:
    text = command(["nm", "-P", "-g", "--undefined-only", path])
    names = set()
    for line in text.splitlines():
        if not line.strip() or line.endswith(":"):
            continue
        fields = line.split()
        reviewed_require(len(fields) >= 2 and SYMBOL.fullmatch(fields[0]) is not None,
                "unrecognized reference")
        names.add(fields[0])
    return names


def reference_inputs(roots: list[Path], excluded: set[Path],
                     inventory: dict | None = None) -> list[Path]:
    """Read-only consumer inventory; reject ambiguous/redirection-based graphs."""
    if __package__:
        from . import cef_frozen_dependencies as replay
    else:  # vcpkg executes the owning replay module as a file.
        import cef_frozen_dependencies as replay
    paths = set()
    for root in roots:
        replay.clean_path(root)
        reviewed_require(root.is_dir(), "consumer root missing")
        for path in root.rglob("*"):
            # This whole-root scan uses the SAME narrowly bound metadata rule.
            # Never follow directory links or accept symbolic ELF inputs.
            if path.is_symlink():
                reviewed_require(verified_metadata_alias(path, root, inventory or {}),
                                 "redirected consumer inventory: " + path.relative_to(root).as_posix())
                continue
            if path.is_file() and path.suffix in {".a", ".o", ".obj", ".so"}:
                if path not in excluded:
                    paths.add(path)
    reviewed_require(len(paths) <= 4096, "consumer inventory too large")
    return sorted(paths)


def audit_incoming(paths: list[Path], forbidden: set[str]) -> int:
    if __package__:
        from . import cef_frozen_dependencies as replay
    else:  # vcpkg executes the owning replay module as a file.
        import cef_frozen_dependencies as replay
    for path in paths:
        if path.suffix == ".a":
            with path.open("rb") as stream:
                reviewed_require(stream.read(8) == b"!<arch>\n", "nonregular consumer archive")
        # A companion archive may define its own COMDAT template. Only its
        # unresolved boundary references can demand a definition from this core.
        reviewed_require(not ((undefined(path) - replay.exports(path)) & forbidden),
                "another consumer requires a discarded private definition")
    return len(paths)


def native_probe(folder: Path, prefix: Path, package: Path, manifest: dict,
                 api: set[str], absent: set[str], target: Path) -> int:
    """Link ALL frozen core objects, not just the few objects reached by a smoke."""
    if __package__:
        from . import cef_frozen_dependencies as replay
    else:  # vcpkg executes the owning replay module as a file.
        import cef_frozen_dependencies as replay
    if __package__:
        from .cef_x11_static import OS_NEEDED
    else:
        from cef_x11_static import OS_NEEDED
    cc = shutil.which("gcc-14") or shutil.which("cc")
    cxx = shutil.which("g++-14") or shutil.which("c++")
    reviewed_require(bool(cc and cxx and shutil.which("ld")), "native toolchain unavailable")
    core = prefix / "lib/libharfbuzz.a"
    # The native linker resolves intra-archive references using the full frozen
    # implementation; it must not introduce any unresolved HarfBuzz internals.
    aggregate = folder / "core.o"
    command(["ld", "-r", "--whole-archive", core, "--no-whole-archive", "-o", aggregate])
    unresolved = undefined(aggregate)
    reviewed_require(not (unresolved & absent) and not any(
        n.startswith(("hb_", "_hb_")) for n in unresolved), "frozen core is not closed")

    headers = sorted(p.name for p in (package / "include/harfbuzz").glob("*.h"))
    declarations = '#define HB_NO_SINGLE_HEADER_ERROR 1\n' + ''.join(
        '#include <harfbuzz/' + n + '>\n' for n in headers)
    # All core public functions are address-taken so --gc-sections cannot silently
    # reduce this ABI test to the subset used by the runtime exercise.
    slots = ',\n'.join('(void (*)(void))&' + n for n in sorted(api))
    c = folder / "api.c"
    c.write_text(declarations + '\nvoid (*volatile api[])(void) = {\n' + slots + '\n};\n' + r'''
extern int cpp_api_probe(void);
int main(void) {
  unsigned major = 0, minor = 0, micro = 0;
  hb_version(&major, &minor, &micro);
  if (major != 14 || minor != 2 || micro != 1 || !api[0]) return 1;
  hb_buffer_t *b = hb_buffer_create();
  if (!b || !hb_buffer_allocation_successful(b)) return 2;
  hb_buffer_add_utf8(b, "abc", 3, 0, 3);
  hb_buffer_guess_segment_properties(b);
  hb_shape(hb_font_get_empty(), b, 0, 0);
  unsigned count = 0;
  const hb_glyph_info_t *info = hb_buffer_get_glyph_infos(b, &count);
  int valid = info && count == 3 && hb_buffer_get_length(b) == 3;
  hb_buffer_destroy(b);
  return valid ? cpp_api_probe() : 3;
}
''', encoding="utf-8")
    cpp = folder / "api.cc"
    cpp.write_text(r'''#include <harfbuzz/hb-cplusplus.hh>
extern "C" int cpp_api_probe(void) {
  hb::shared_ptr<hb_buffer_t> a(hb_buffer_create());
  hb::shared_ptr<hb_buffer_t> b(a);
  hb::unique_ptr<hb_buffer_t> c(hb_buffer_create());
  return !a || !b || !c || a.get() != b.get();
}
''', encoding="utf-8")
    includes = ["-I" + str(package / "include"), "-I" + str(prefix / "include"),
                "-I" + str(prefix / "include/freetype2")]
    command([cc, "-O2", *includes, "-c", c, "-o", folder / "api.o"])
    command([cxx, "-std=c++17", "-O2", "-fno-exceptions", "-fno-rtti", *includes,
             "-c", cpp, "-o", folder / "cpp.o"])
    audit_incoming([folder / "api.o", folder / "cpp.o"], absent)
    module = manifest["modules"]["harfbuzz"]
    libraries = module["libraries"]
    reviewed_require(libraries[0] == "lib/libharfbuzz.a" and module["link_options"] == ["-pthread"],
            "unreviewed core link interface")
    dependencies = []
    for name in libraries[1:]:
        if name == "m":
            dependencies.append("-lm")
        else:
            reviewed_require(name in manifest["archive_objects"], "unbound external archive")
            path = replay.member(prefix, name)
            replay.checked(path, manifest["files"][name])
            dependencies.append(str(path))
    executable = folder / "boundary-proof"
    command([cc, folder / "api.o", folder / "cpp.o", "-Wl,--start-group",
             "-Wl,--whole-archive", core, "-Wl,--no-whole-archive", *dependencies,
             "-Wl,--end-group", "-pthread", "-o", executable], timeout=180)
    needed = re.findall(r"\(NEEDED\).*?Shared library:\s*\[([^\]]+)\]",
                        command(["readelf", "-d", executable]))
    reviewed_require(not (set(needed) - OS_NEEDED), "native ABI probe imports a non-OS library")
    command([executable], timeout=30)
    return len(api)


def _verify(spec: dict, value: dict, package: Path, port: str, features: str,
           version: str, name: str, built: set[str], frozen: set[str]) -> dict:
    if __package__:
        from . import cef_frozen_dependencies as replay
    else:  # vcpkg executes the owning replay module as a file.
        import cef_frozen_dependencies as replay
    reviewed_require(port == "harfbuzz" and name == "lib/libharfbuzz.a" and version == "14.2.1"
            and features.split(";") and set(features.split(";")) == {"core", "c-linker", "freetype"},
            "unreviewed package profile")
    prefix = Path(spec["prefix"])
    installed = Path(spec.get("installed", ""))
    reviewed_require(installed.is_absolute(), "bound installed consumer root required")
    source, target = replay.member(prefix, name), replay.member(package, name)
    reviewed_require(replay.sha(source) == REVIEW["archive_sha256"], "unreviewed frozen core")
    missing, extra = built - frozen, frozen - built
    for label, names in (("built_only", missing), ("frozen_only", extra)):
        reviewed_require(len(names) == REVIEW[label + "_count"] and
                digest_names(names) == REVIEW[label + "_sha256"], "unreviewed symbol difference")
        details = replay.elf_details(target if label == "built_only" else source, names)
        reviewed_require(all(n.startswith("_Z") and entries == [
            {"type": "FUNC", "binding": "WEAK", "visibility": "HIDDEN"}]
            for n, entries in details.items()), "difference is not the reviewed private implementation")
    headers = {n: r for n, r in value["files"].items() if n.startswith("include/harfbuzz/")}
    reviewed_require(hashlib.sha256(replay.canonical(headers)).hexdigest() == REVIEW["headers_sha256"],
            "unreviewed public header inventory")
    present = {p.relative_to(package).as_posix() for p in
               (package / "include/harfbuzz").rglob("*") if p.is_file()}
    reviewed_require(present == set(headers), "installed public boundary changed")
    declarations = set()
    for n, record in headers.items():
        replay.checked(replay.member(package, n), record)
        replay.checked(replay.member(prefix, n), record)
        if n.endswith(".h"):
            declarations.update(API.findall((package / n).read_text()))
    api = {n for n in built if n.startswith("hb_")}
    reviewed_require(api and api <= frozen and api <= declarations,
            "public C ABI definitions or declarations changed")
    built_public = replay.elf_details(target, api)
    reviewed_require(built_public == replay.elf_details(source, api), "public ELF ABI attributes changed")
    incoming = reference_inputs([prefix, package, installed], {source, target}, value)
    count = audit_incoming(incoming, missing)
    # Nothing is installed until every proof succeeds. Compiler outputs and native
    # executables are private temporary scratch, not package or frozen contents.
    with tempfile.TemporaryDirectory(prefix="cef-hb-boundary-") as directory:
        public_count = native_probe(Path(directory), prefix, package, value, api, missing, target)
    return {"profile": PROFILE, "policy_sha256": replay.sha(Path(__file__)),
            "archive_sha256": replay.sha(source), "public_api_count": public_count,
            "private_definitions_reviewed": len(missing), "incoming_inputs_checked": count,
            "public_headers_verified": len(headers), "static_link_and_api_verified": True}


def reviewed_verify(spec: dict, value: dict, package: Path, port: str, features: str,
           version: str, name: str, built: set[str], frozen: set[str],
           *, diagnostics: Path | None = None) -> dict:
    """Detailed failed native proofs stay in the encrypted-only diagnostic tree."""
    if __package__:
        from . import cef_frozen_dependencies as replay
    else:  # vcpkg executes the owning replay module as a file.
        import cef_frozen_dependencies as replay
    trace: list[dict] = []
    token = _TRACE.set(trace)
    try:
        return _verify(spec, value, package, port, features, version, name, built, frozen)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if diagnostics is not None:
            diagnostics = replay.clean_path(diagnostics)
            for key in ("prefix", "packages", "installed"):
                if key in spec:
                    root = Path(spec[key])
                    reviewed_require(not diagnostics.is_relative_to(root)
                            and not root.is_relative_to(diagnostics), "unsafe diagnostic destination")
            diagnostics.mkdir(mode=0o700, parents=True, exist_ok=True)
            payload = {"schema": 1, "kind": "harfbuzz-boundary-failure",
                       "profile": PROFILE, "error_type": type(error).__name__,
                       "reason": str(error) if isinstance(error, ValueError) else "native-command-exception",
                       "commands": trace, "runtime_verified": False}
            fd = os.open(diagnostics / "harfbuzz.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(replay.canonical(payload))
        raise
    finally:
        _TRACE.reset(token)
