"""Source-level guards for public-builder strict CEF qualification workflows."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StrictQualificationWorkflowTests(unittest.TestCase):
    def test_full_platform_workflow_is_exact_and_keeps_native_output_private(self):
        text = (ROOT / ".github/workflows/cef-strict-platform-qualification.yml").read_text()
        self.assertIn("repository: dobord/vcpkg", text)
        self.assertIn("ref: 736b290cf7338c26565c831d48c8ef52b8a353a5", text)
        self.assertIn("repository: microsoft/vcpkg", text)
        self.assertIn("ref: 9e593bb18ea69cc5095e012465dcd675a822ed0d", text)
        self.assertIn("repository: dobord/cef", text)
        self.assertIn("ref: c74fc487b25fc6e3dbbdd4d02c4e963735a66b96", text)
        self.assertIn('>"$RUNNER_TEMP/cef-strict-native.log" 2>&1', text)
        self.assertNotIn("actions/cache", text)
        self.assertNotIn("upload-artifact", text)
        self.assertIn("gh api \"repos/dobord/vcpkg/actions/artifacts/$id/zip\"", text)
        self.assertIn("sha256sum -c -", text)
        self.assertIn('cat "$RUNNER_TEMP/cef-gn-evidence/gn-qualification.json"', text)
        self.assertNotIn("persist-credentials: true", text)

    def test_production_build_accepts_trusted_large_disk_runner_labels(self):
        text=(ROOT/'.github/workflows/build-release.yml').read_text()
        self.assertIn('runs-on: ${{ fromJSON(matrix.runner_labels) }}',text)
        self.assertIn("vars.CEF_STATIC_LINUX_RUNNER_LABELS || '[\"ubuntu-24.04\"]'",text)
        self.assertIn("vars.CEF_STATIC_WINDOWS_RUNNER_LABELS || '[\"windows-2022\"]'",text)
        self.assertNotIn('runs-on: ${{ matrix.os }}',text)

    def test_strict_engine_iteration_uploads_only_encrypted_checkpoint(self):
        workflow=(ROOT/'.github/workflows/cef-strict-engine-iteration.yml').read_text()
        worker=(ROOT/'secure_release/cef_strict_iteration.py').read_text()
        self.assertIn('ref: 736b290cf7338c26565c831d48c8ef52b8a353a5',workflow)
        self.assertIn('run: python -m secure_release.cef_strict_iteration',workflow)
        self.assertIn('Restore reviewed completed-package caches by exact artifact digest',workflow)
        self.assertIn('gh api "repos/dobord/vcpkg/actions/artifacts/$id/zip"',workflow)
        self.assertIn('sha256sum -c -',workflow)
        self.assertIn('"--binary-cache"',worker)
        self.assertIn('cef-strict-checkpoint-encrypted/*.enc',workflow)
        self.assertNotIn('path: ${{ runner.temp }}/cef-strict-checkpoint/*',workflow)
        self.assertIn('cef_cache.seal(',worker)
        self.assertIn('cef_cache.unseal(',worker)
        self.assertIn('check_run(',worker)
        self.assertIn('"cef-strict-engine-iteration.yml"',worker)
        self.assertIn('"cef-checkpoint", "linux"',worker)
        self.assertIn('"slice"',worker)
        self.assertIn('"restore"',worker)
        self.assertIn('"platform_build_inputs"',worker)
        self.assertIn('"third_party_modules_static"',worker)
        self.assertIn('"platform-graph-receipt.json"',worker)
        self.assertIn('"gn_graph_qualified"',worker)
        self.assertIn('"failure_stage"',worker)
        self.assertNotIn('print(text',worker)
        lock=(ROOT/'ci/cef-strict-engine-lock.json').read_text()
        self.assertIn('"checkpoint": null',lock)
        self.assertIn('"vcpkg_commit": "736b290cf7338c26565c831d48c8ef52b8a353a5"',lock)

    def test_sdk_dependency_qualification_keeps_private_build_logs_runner_local(self):
        text = (ROOT / ".github/workflows/cef-strict-sdk-deps.yml").read_text()
        self.assertIn("repository: dobord/lockfreecoro", text)
        self.assertIn("repository: dobord/lfc-ui", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("sdk-deps-install.log", text)
        self.assertIn("sdk-deps-consumer-build.log", text)
        self.assertIn("SDK_DEPS_LINUX_QUALIFIED", text)
        self.assertIn("SDK_DEPS_WINDOWS_QUALIFIED", text)
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("cat $RUNNER_TEMP/sdk-deps", text)

    def test_combined_qualification_runs_only_for_explicit_checkpoint_lock(self):
        text=(ROOT/'.github/workflows/cef-strict-combined.yml').read_text()
        self.assertIn('workflow_dispatch:',text)
        self.assertIn('- ci/cef-strict-engine-lock.json',text)
        self.assertIn('run: python -m secure_release.cef_strict_combined',text)
        self.assertIn('cef-strict-combined-summary-',text)
        self.assertNotIn('cipher-output',text)
        self.assertNotIn('compiler.log',text)
        worker=(ROOT/'secure_release/cef_strict_combined.py').read_text()
        self.assertIn('freerdp_proxy_web_engine_view_cef.cpp',worker)
        self.assertIn("'lfc-ui-freerdp-cef-consumer'",worker)
        self.assertIn('freerdp-server-proxy',worker)
        self.assertIn('freerdp-shadow',worker)
        self.assertIn('-static-libstdc++ -static-libgcc',worker)
        self.assertIn('libavcodec',worker)
        self.assertIn('xvfb-run',worker)

    def test_windows_msvc_stl_graph_gate_is_source_based_and_fail_closed(self):
        text = (ROOT / ".github/workflows/cef-windows-msvc-stl.yml").read_text()
        self.assertIn("ref: dfdcc240141f5a15f976387d21c60a2b92205d5f", text)
        self.assertIn("source_build.py prepare", text)
        self.assertIn("source_build.py check", text)
        self.assertIn("use_custom_libcxx", text)
        self.assertIn("third_party/libc++", text)
        self.assertIn("static-link-inputs.json", text)
        self.assertIn("CEF_WINDOWS_MSVC_STL_GRAPH_QUALIFIED", text)
        self.assertNotIn("upload-artifact", text)

    def test_lfc_ui_static_cef_workflow_builds_upstream_example(self):
        text = (ROOT / ".github/workflows/lfc-ui-static-cef.yml").read_text()
        self.assertIn("ref: c7fb5af43431773dd68b3afe746ef71ecd786dc9", text)
        self.assertIn("ref: c74fc487b25fc6e3dbbdd4d02c4e963735a66b96", text)
        self.assertIn("'lfc-ui[cef]'", text)
        self.assertIn("web_engine_view_cef.cpp", text)
        self.assertIn("find_package(lfc-ui CONFIG REQUIRED COMPONENTS WebEngine)", text)
        self.assertIn("TARGET CEF::cpp", text)
        self.assertIn("cef_static_deploy_resources(web_engine_view_cef)", text)
        self.assertIn("LFC_UI_CEF_SHARED_TARGET_PAYLOAD", text)

    def test_current_private_source_contract_workflow_pins_gn_gate_revision(self):
        text = (ROOT / ".github/workflows/cef-strict-source-contracts.yml").read_text()
        self.assertIn("repository: dobord/vcpkg", text)
        self.assertIn("ref: 736b290cf7338c26565c831d48c8ef52b8a353a5", text)
        self.assertIn("ref: 457fd41f39cbcff940c7af654da899d44ba5e553", text)
        self.assertNotIn("git -C private-vcpkg/.full-cef apply --check", text)
        self.assertNotIn("strict-import-cef", text)
        self.assertIn("static-third-party release reuse is Windows-only", text)
        self.assertIn("strict_requalification_required", text)
        self.assertIn("CEF::cpp", text)
        self.assertIn("cpp_support", text)
        self.assertIn("python -I -m unittest discover -s ci/cef-full/tests -v", text)
        self.assertIn("ci/cef-full/gn_check.py", text)
        self.assertNotIn("upload-artifact", text)
        self.assertNotIn("actions/cache", text)


if __name__ == "__main__":
    unittest.main()
