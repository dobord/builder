"""Real toy archives through the full pinned exporter. NOT a CEF runtime proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

recipe, builder = map(lambda value: Path(value).resolve(), sys.argv[1:3])
sys.path.insert(0, str(builder))
from secure_release import cef_combined_port as port
from secure_release import cef_qualified_export as qualified
from secure_release import cef_gtk_codecs as codecs
from secure_release import cef_native_link_static as native
from secure_release import cef_nss_isolation as nss
sys.path.insert(0, str(recipe / 'vcpkg/static'))
import gn_platform
import platform_contract as contract
import platform_export


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(args, cwd, okay=True):
    proc = subprocess.run(list(map(str, args)), cwd=cwd, capture_output=True, text=True, timeout=90)
    if okay:
        assert proc.returncode == 0, proc.stdout + proc.stderr
    else:
        assert proc.returncode != 0, 'Expected native command failure'
    return proc


def refuses(call, text=None):
    try:
        call()
    except (ValueError, RuntimeError) as e:
        if text is not None:
            assert text in str(e), str(e)
    else:
        raise AssertionError('Unverified export was accepted')


with tempfile.TemporaryDirectory(prefix='qualified-export-') as folder:
    root = Path(folder)
    source = root / 'source'
    out = source / 'out/CEF_Static_Platform_Release_x64'
    prefix, logs, sdk = [root / name for name in ('target-prefix', 'logs', 'package')]
    for path in (out, logs, prefix/'lib/cef-nss', prefix/'lib/pkgconfig', prefix/'include',
                 source/'third_party/ninja', source/'cef/include/base/internal',
                 source/'cef/include/capi', source/'net/base'):
        path.mkdir(parents=True, exist_ok=True)
    shutil.copy2(shutil.which('ninja'), source/'third_party/ninja/ninja')
    bodies = {
        'jpeg': 'int jpeg_std_error(void){return 3;}\n',
        'tiff': 'int TIFFOpen(void){return 5;}\n',
        'nss': 'int SHA256_Update(void){return 11;}\n',
        'gdk': 'int jpeg_std_error(void); int TIFFOpen(void);\n'
               'int gdk_pixbuf_new(void){return jpeg_std_error()+TIFFOpen();}\n',
        'external': 'int external_value(void){return 23;}\n',
        'engine': 'int jpeg_std_error(void){return 100;} int TIFFOpen(void){return 200;}\n'
                  'int SHA256_Update(void){return 300;}\n'
                  'int gdk_pixbuf_new(void); int CEF_NSS_SHA256_Update(void); int external_value(void);\n'
                  'int engine_value(void){return gdk_pixbuf_new()+CEF_NSS_SHA256_Update()+external_value();}\n',
        'smoke': 'int engine_value(void); int main(void){return engine_value()!=42;}\n',
    }
    bodies['nss'] += ''.join('int '+name+'(void){return 0;}\n'
                             for name in nss.SYMBOL_RENAMES if name != 'SHA256_Update')
    archives = {'lib/libjpeg.a':'jpeg', 'lib/libtiff.a':'tiff',
                'lib/cef-nss/libcef_nss.a':'nss', 'lib/libgdk_pixbuf-2.0.a':'gdk',
                'lib/libexternal.a':'external'}
    for name, body in bodies.items():
        (out/(name+'.c')).write_text(body)
        if name != 'smoke':
            run(['cc', '-c', name+'.c', '-o', name+'.o'], out)
    for name, stem in archives.items():
        run(['ar','rcs',prefix/name,stem+'.o'],out)
    run(['ar','rcs','libengine.a','engine.o'],out)
    (prefix/'include/fixture.h').write_text('int external_value(void);\n')
    (prefix/'lib/pkgconfig/fixture.pc').write_text(
        'prefix=${pcfiledir}/../..\nlibdir=${prefix}/lib\nincludedir=${prefix}/include\n'
        'Name: fixture\nDescription: native fixture\nVersion: 1.0\n'
        'Libs: -L${libdir} -ljpeg -ltiff -lgdk_pixbuf-2.0 ${libdir}/cef-nss/libcef_nss.a -lexternal -pthread\n'
        'Cflags: -I${includedir}\n')
    value = contract.capture(prefix, Path(shutil.which('pkg-config')), ['fixture'])
    value['modules'] = {name:copy.deepcopy(value['modules']['fixture']) for name in gn_platform.MODULES}
    manifest = root/'platform.json'
    manifest.write_bytes(contract.canonical(value))
    selection = {'manifest':str(manifest),'prefix':str(prefix),'sha256':contract.digest(manifest)}
    llvm = source/'third_party/llvm-build/Release+Asserts/bin'
    llvm.mkdir(parents=True)
    for name, tool in (('llvm-nm','nm'),('llvm-objcopy','objcopy'),('llvm-ar','ar')):
        shutil.copy2(shutil.which(tool),llvm/name)
    # Use the real NSS + codec wrapper policies, symbol transforms and receipts.
    # The provider implementations are small native fixtures, not real libraries.
    (out/'build.ninja').write_text(
        'rule cc\n  command = cc -c $in -o $out\n'
        'rule link\n  command = cc -o $out -Wl,--start-group $in -Wl,--end-group\n'
        'build cef_static_smoke.smoke.o: cc smoke.c\n'
        'build cef_static_smoke: link cef_static_smoke.smoke.o libengine.a '+
        ' '.join(str(prefix/name) for name in sorted(qualified.EXPECTED_INPUTS))+
        ' '+str(prefix/'lib/libexternal.a')+'\n')
    summary = {}
    nss.install(source,manifest,prefix,selection['sha256'],summary)
    run([source/'third_party/ninja/ninja','-C',out,'cef_static_smoke'],source)
    nss.record_receipt(source,summary,required=True)
    spec = port.collect_bindings(source,manifest,prefix,selection['sha256'])
    bindings = spec['bindings']
    assert summary['gtk_codec_namespace_archives']==3
    assert set(bindings)==qualified.EXPECTED_INPUTS
    run([out/'cef_static_smoke'],out)
    graph = {'libs':[str(prefix/name) for name in sorted(qualified.EXPECTED_INPUTS)]+['external','m'],
             'ldflags':['-pthread']}
    proof = gn_platform.audit_graph(graph,source,out,prefix,value)
    proof['manifest_sha256'] = selection['sha256']
    original_export = load('original_export',recipe/'vcpkg/ports/cef-static/export_static.py')
    receipt = {'cef_commit':original_export.CEF_COMMIT,'chromium_commit':original_export.CHROMIUM_COMMIT,
               'source_build_verified':True,'engine_linkage':'static',
               'executable_sha256':contract.digest(out/'cef_static_smoke'),
               'smoke':{'cef':original_export.CEF_VERSION,'engine':'static',
                        'javascript':True,'paint':True,'browser_modules_clean':True,
                        'renderer_modules_clean':True,'browser_pid':1,'renderer_pid':2,
                        'third_party_modules_static':True},
               'platform_build_inputs':selection,'platform_graph':proof}
    # Deliberately synthetic runtime receipt authorizes only this disposable test.
    # No result of this script is evidence about real Chromium/CEF functionality.
    (logs/'engine-build-receipt.json').write_text(json.dumps(receipt))
    (logs/'gn-graph.json').write_text(json.dumps({'//cef:cef_static_smoke':graph}))
    for name in ('cef_version.h','cef_config.h','cef_api_versions.h','capi/cef_app_capi.h'):
        (source/'cef/include'/name).write_text('/* synthetic public header */\n')
    for name in ('LICENSE','cef/LICENSE.txt','net/base/net_error_list.h'):
        (source/name).write_text('/* public fixture */\n')
    # Original exporter reintroduces the original graph aliases and a bare -l.
    original_export.export(source,out,logs,root/'old-package',platform_inputs=selection)
    old_inventory = json.loads((root/'old-package/share/cef-static/static-platform-inventory.json').read_text())
    assert qualified.EXPECTED_INPUTS <= {v['path'] for v in old_inventory['archives']}
    assert 'external' in json.loads((root/'old-package/share/cef-static/static-link-inventory.json').read_text())['system_libraries']
    # Standard Git patch to a distinct pristine acquisition tree. Archive/producer stay untouched.
    acquisition = root/'acquired'
    shutil.copytree(recipe/'vcpkg',acquisition/'vcpkg')
    before, after = port.recipe_payload(recipe,spec)
    patch = root/'qualified.patch'; patch.write_bytes(port.make_patch(before,after))
    run(['git','-c','core.autocrlf=false','apply','--check',patch],acquisition)
    run(['git','-c','core.autocrlf=false','apply',patch],acquisition)
    for name, data in after.items():
        assert (acquisition/name).read_bytes()==data
    patched_export = load('patched_export',acquisition/'vcpkg/ports/cef-static/export_static.py')
    patched_export.export(source,out,logs,sdk,platform_inputs=selection)
    inventory = json.loads((sdk/'share/cef-static/static-platform-inventory.json').read_text())
    assert inventory['native_isolation_verified'] is True
    assert len(inventory['isolated_archives'])==4
    assert not qualified.EXPECTED_INPUTS.intersection(v['path'] for v in inventory['archives'])
    full = json.loads((sdk/'share/cef-static/static-link-inventory.json').read_text())
    assert full['system_libraries']==['m'] and full['archives']==5
    for item in inventory['isolated_archives']:
        assert contract.digest(sdk/item['path']) == bindings[item['source']]['sha256']
    assert (sdk/'share/cef-static/platform-build-inputs.json').read_bytes()==manifest.read_bytes()
    spec_sha = hashlib.sha256(codecs.canonical(spec)).hexdigest()
    assert port.verify_packaged_isolation(sdk, selection['sha256'], spec_sha)==4
    record=inventory['isolated_archives'][0]
    actual=sdk/record['path']; saved=actual.read_bytes(); actual.write_bytes(saved+b'changed')
    refuses(lambda: port.verify_packaged_isolation(sdk,selection['sha256'],spec_sha),'archive changed')
    actual.write_bytes(saved)
    refuses(lambda: port.verify_packaged_isolation(sdk,selection['sha256'],'0'*64),'derivation differs')
    def prepared(record=spec):
        base = platform_export.prepare(selection,receipt,graph,source,out)
        return qualified.QualifiedPlatform(base,copy.deepcopy(record),source,out)
    files = original_export.query_link_inputs(run(['ninja','-t','query','cef_static_smoke'],out).stdout)
    refuses(lambda: prepared().bind_query(files+[str(prefix/'lib/libjpeg.a')]),'mixes original')
    refuses(lambda: prepared().bind_query([v for v in files if 'isolated' not in v]),'missing a qualified')
    bound=prepared(); bound.bind_query(files)
    refuses(lambda: bound.bind_query(files),'bound twice')
    refuses(lambda: bound.library_input('unreviewed'),'no verified')
    refuses(lambda: bound.finish(),'Incomplete')
    bad=copy.deepcopy(spec); bad['schema']=True
    refuses(lambda: prepared(bad),'differs')
    bad=copy.deepcopy(spec); bad['bindings']['lib/libtiff.a']['sha256']='0'*64
    refuses(lambda: prepared(bad),'changed')
    bad=copy.deepcopy(spec); bad['bindings']['lib/libtiff.a']['native']='../../unsafe.a'
    refuses(lambda: prepared(bad),'destination')
    target=out/bindings['lib/libjpeg.a']['native']
    raw=target.read_bytes(); target.write_bytes(raw+b'changed')
    refuses(prepared,'changed'); target.write_bytes(raw)
    header=prefix/'include/fixture.h'; raw=header.read_bytes(); header.write_bytes(b'changed')
    refuses(prepared); header.write_bytes(raw)
    # Now re-link with source, old prefix and producer package hidden.
    relocated=root/'relocated'; shutil.copytree(prefix,relocated)
    shutil.copytree(sdk,relocated,dirs_exist_ok=True)
    project=root/'consumer'; project.mkdir()
    (project/'main.c').write_text(bodies['smoke'])
    (project/'CMakeLists.txt').write_text('cmake_minimum_required(VERSION 3.24)\nproject(fixture C)\n'
        'find_package(cef-static CONFIG REQUIRED)\nadd_executable(consumer main.c)\n'
        'target_link_libraries(consumer PRIVATE CEF::static)\n')
    def consumer(location,build,okay=True):
        run(['cmake','-S',project,'-B',build,'-G','Ninja','-Dcef-static_DIR='+str(location/'share/cef-static'),
             '-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF','-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF'],root)
        result=run(['cmake','--build',build],root,okay=okay)
        if okay: run([build/'consumer'],root)
        return result
    old=root/'old-sdk'; shutil.copytree(prefix,old); shutil.copytree(root/'old-package',old,dirs_exist_ok=True)
    failure=consumer(old,root/'old-consumer-build',okay=False)
    assert 'external' in failure.stdout+failure.stderr
    source.rename(root/'source.hidden'); prefix.rename(root/'prefix.hidden'); sdk.rename(root/'package.hidden')
    assert port.verify_packaged_isolation(relocated,selection['sha256'],spec_sha)==4
    consumer(relocated,root/'consumer-build')
    imported=(relocated/'share/cef-static/cef-static-config.cmake').read_text()
    assert str(root) not in imported
    assert not any('${_cef_static_prefix}/'+name+'"' in imported for name in qualified.EXPECTED_INPUTS)
    assert 'libgcc_s' not in run(['readelf','-d',root/'consumer-build/consumer'],root).stdout
    print('QUALIFIED_EXPORT_NATIVE_RELOCATION_VERIFIED')
