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
            require(not path.is_symlink(),'Redirected surviving HarfBuzz consumer')
            if path.is_file() and path.suffix in {'.a','.o'}:
                require(path.suffix == '.a','Unreviewed loose object in HarfBuzz consumers')
                others.append(path)
    api,proof = closed_difference(built,frozen,declared,others)
    require({'hb_shape','hb_buffer_create','hb_ft_font_create',
             'hb_ft_face_create','hb_version_string'} <= api,
            'HarfBuzz declared core/FreeType feature API is missing')
    link_probe(prefix,inventory,api,output)
    return {'schema':1,'kind':'harfbuzz-14.2.1-closed-c-boundary',
            **proof,'public_link_verified':True,'runtime_verified':False,
            'built_sha256':digest(built),'frozen_sha256':digest(frozen),
            'interface_sha256':INTERFACE_SHA256,'policy_sha256':digest(Path(__file__))}
