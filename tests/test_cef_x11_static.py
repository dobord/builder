import pathlib
import tempfile
import unittest

from secure_release import cef_x11_static as x11


class X11StaticTransformTests(unittest.TestCase):
    def test_generator_keeps_default_and_adds_explicit_direct_mode(self):
        text = '''template("generate_library_loader") {\n  action("${target_name}_loader") {\n    args = [\n      "--name",\n      invoker.name,\n      # Note GYP build exposes a per-target variable to control this, which, if\n      # manually set to true, will disable dlopen(). Its not clear this is\n      # needed, so here we just leave off. If this can be done globally, we can\n      # expose one switch for this value, otherwise we need to add a template\n      # param for this.\n      "--link-directly=0",\n    ]\n  }\n}\n'''
        out = x11.patch_loader_gni(text)
        self.assertIn('defined(invoker.link_directly)', out)
        self.assertIn('_link_directly = "--link-directly=1"', out)
        self.assertIn('_link_directly,', out)
        self.assertNotIn('"--link-directly=0",\n    ]', out)

    def test_x_build_direct_links_only_static_profile(self):
        text = '''import("//build/config/ui.gni")\n\ngenerate_library_loader("xlib_loader") {\n  functions = [\n    "XInitThreads",\n    "XOpenDisplay",\n    "XCloseDisplay",\n    "XFlush",\n    "XSynchronize",\n    "XSetErrorHandler",\n    "XFree",\n    "XPending",\n  ]\n}\n\ncomponent("x") {\n  configs += [ ":x11_private_config" ]\n  libs = [ "xcb" ]\n}\n'''
        out = x11.patch_x_build(text)
        self.assertIn('import("//build/config/linux/pkg_config.gni")', out)
        self.assertIn('link_directly = cef_static_platform_manifest != ""', out)
        self.assertIn('configs += [ ":cef_x11_static" ]', out)
        self.assertIn('defines = [ "CEF_STATIC_X11_DIRECT=1" ]', out)
        self.assertIn('packages = [\n      "x11",\n      "xcb",', out)
        self.assertIn('} else {\n    libs = [ "xcb" ]', out)

    def test_xlib_xcb_bridge_is_not_loaded_in_direct_profile(self):
        text = '''void InitXlib() {\n  auto* xlib_xcb_loader = GetXlibXcbLoader();\n  CHECK(xlib_xcb_loader->Load("libX11-xcb.so.1"));\n\n  CHECK(xlib_loader->XInitThreads());\n}\nstruct xcb_connection_t* XlibDisplay::GetXcbConnection() {\n  return GetXlibXcbLoader()->XGetXCBConnection(display_);\n}\n'''
        out = x11.patch_xlib_support(text)
        self.assertIn('#if !defined(CEF_STATIC_X11_DIRECT)', out)
        self.assertIn('#if defined(CEF_STATIC_X11_DIRECT)', out)
        self.assertIn('CHECK(false)', out)
        self.assertEqual(out.count(x11.MARKER), 2)

    def test_anchor_changes_fail_closed(self):
        with self.assertRaises(ValueError):
            x11.patch_loader_gni('template("generate_library_loader") {}')
        with self.assertRaises(ValueError):
            x11.patch_x_build('import("//build/config/ui.gni")\n')
        with self.assertRaises(ValueError):
            x11.patch_xlib_support('void InitXlib() {}')

    def test_platform_requires_captured_x11_and_xcb_archives(self):
        # Validation is covered with a deliberately tiny synthetic manifest;
        # archive bytes are still hash/size bound exactly as in production.
        import hashlib, json
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            prefix = root / 'prefix'; (prefix / 'lib').mkdir(parents=True)
            records = {}
            archives = {}
            for name in ('libX11.a', 'libxcb.a'):
                data = ('archive-' + name).encode()
                path = prefix / 'lib' / name; path.write_bytes(data)
                rel = 'lib/' + name
                records[rel] = {'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                archives[rel] = 1
            value = {
                'schema': 1, 'kind': 'linux-x64-static-platform-build-inputs',
                'runtime_verified': False,
                'modules': {
                    'x11': {'libraries': ['lib/libX11.a', 'lib/libxcb.a']},
                    'xcb': {'libraries': ['lib/libxcb.a']},
                },
                'files': records, 'archive_objects': archives,
            }
            manifest = root / 'manifest.json'
            manifest.write_text(json.dumps(value))
            sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            result = x11._validated_platform(manifest, prefix, sha)
            self.assertEqual(result['module_count'], 2)
            self.assertEqual(result['archives'], ['lib/libX11.a', 'lib/libxcb.a'])
            value['modules']['xcb']['libraries'] = ['lib/libmissing.a']
            manifest.write_text(json.dumps(value))
            sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                x11._validated_platform(manifest, prefix, sha)


if __name__ == '__main__':
    unittest.main()
