"""Source-backed gcovr names are not raw credentials; transport is unchanged."""
import contextlib
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from secure_release import project_ci as ci, project_ci_runner as runner


def detail_name(relative):
    identity = hashlib.md5(relative.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"coverage.{Path(relative).name}.{identity}.html"


class CoverageReportsTests(unittest.TestCase):
    def fixture(self, temporary, relative="include/synthetic/id_token.hpp"):
        root = Path(temporary)
        source = root / "source"
        report = source / "out/coverage"
        report.mkdir(parents=True)
        (root / "project-ci").mkdir()
        code = source / relative
        code.parent.mkdir(parents=True)
        code.write_text("// PUBLIC_SYNTHETIC_SOURCE\n", encoding="utf-8")
        self.metadata(report, {"gcovr/format_version": "0.6", "files": [{"file": relative}]})
        (report / "coverage.html").write_text("PUBLIC_SYNTHETIC_INDEX", encoding="utf-8")
        name = detail_name(relative)
        (report / name).write_text("PUBLIC_SYNTHETIC_DETAIL", encoding="utf-8")
        return root, source, report, name

    def metadata(self, report, value):
        (report / "coverage.json").write_text(json.dumps(value, ensure_ascii=True), encoding="utf-8")

    def archive(self, root, source, paths, encrypt):
        environment = {"RUNNER_TEMP": str(root), "GITHUB_SHA": "b" * 40,
                       "CI_REQUEST_DIGEST": "d" * 64, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1"}
        with patch.dict(os.environ, environment), patch.object(runner.crypto, "encrypt_file", side_effect=encrypt), patch.object(runner.crypto, "unb64", return_value=b"PUBLIC_SYNTHETIC_RECIPIENT"):
            runner.artifact_archive(source, paths, root / "cipher/reports.enc",
                {"source_sha": "a" * 40, "source_id": 1}, {"id": "synthetic", "runner": ["ubuntu-24.04"]})

    def assert_rejected(self, root, source, report, reason="credential-like report member"):
        encrypt = Mock()
        with self.assertRaisesRegex(ValueError, reason):
            self.archive(root, source, [report], encrypt)
        encrypt.assert_not_called()

    def test_source_pages_preserve_recipient_context_and_sha256_manifest(self):
        for relative in ("include/synthetic/id_token.hpp", "src/token_store.cpp", "include/synthetic/cl\u00e9_token.hpp"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as tmp:
                root, source, report, name = self.fixture(tmp, relative)
                calls = []
                def encrypt(plain, target, recipient, context):
                    self.assertEqual(target, root / "cipher/reports.enc")
                    self.assertEqual(recipient, "PUBLIC_SYNTHETIC_RECIPIENT")
                    self.assertEqual(context, {"schema": 1, "purpose": "project-ci-reports",
                        "builder_sha": "b" * 40, "request_digest": "d" * 64, "run": 1, "attempt": 1})
                    with tarfile.open(plain) as archive:
                        members = {member.name: member for member in archive.getmembers()}
                        self.assertEqual(set(members), {"manifest.json", "reports/0/coverage.json",
                            "reports/0/coverage.html", "reports/0/" + name})
                        manifest = json.load(archive.extractfile(members["manifest.json"]))
                        self.assertEqual(manifest["source_sha"], "a" * 40)
                        self.assertEqual(manifest["source_id"], 1)
                        self.assertEqual(manifest["lane"], "synthetic")
                        self.assertEqual(manifest["runner"], ["ubuntu-24.04"])
                        for entry in manifest["files"]:
                            content = archive.extractfile(members[entry["name"]]).read()
                            self.assertEqual(entry["size"], len(content))
                            self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
                            self.assertNotIn("md5", entry)
                    calls.append(True)
                console = io.StringIO()
                with contextlib.redirect_stdout(console), contextlib.redirect_stderr(console):
                    self.archive(root, source, [report], encrypt)
                self.assertEqual(console.getvalue(), "")
                self.assertEqual(calls, [True])
                self.assertFalse((root / "project-ci/reports.tar").exists())

    def test_raw_credential_names_unmapped_html_and_wrong_filename_hash_are_denied(self):
        for forbidden in ("credentials.json", "client_token.json", "private-key.pem", "id_token.hpp",
                          "coverage.id_token.hpp." + "0" * 32 + ".html", "token.html"):
            with self.subTest(name=forbidden), tempfile.TemporaryDirectory() as tmp:
                root, source, report, _ = self.fixture(tmp)
                (report / forbidden).write_text("PUBLIC_SYNTHETIC_FORBIDDEN", encoding="utf-8")
                self.assert_rejected(root, source, report)

    def test_malformed_metadata_never_grants_an_exception(self):
        values = [None, [], False, 1, {}, {"gcovr/format_version": "unknown", "files": []},
                  {"gcovr/format_version": "0.6", "files": None},
                  {"gcovr/format_version": "0.6", "files": [None]},
                  {"gcovr/format_version": "0.6", "files": [{"file": []}]},
                  {"gcovr/format_version": "0.6", "files": [{"file": {}}]}]
        for value in values:
            with self.subTest(value=type(value).__name__), tempfile.TemporaryDirectory() as tmp:
                root, source, report, _ = self.fixture(tmp)
                self.metadata(report, value)
                self.assert_rejected(root, source, report)

    def test_invalid_json_duplicate_keys_and_nonfinite_numbers_are_denied(self):
        for text in ("not JSON", '{"files":[],"files":[]}', '{"files":NaN}'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                root, source, report, _ = self.fixture(tmp)
                (report / "coverage.json").write_text(text, encoding="utf-8")
                self.assert_rejected(root, source, report)

    def test_missing_metadata_or_index_never_grants_an_exception(self):
        for missing in ("coverage.json", "coverage.html"):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as tmp:
                root, source, report, _ = self.fixture(tmp)
                (report / missing).unlink()
                self.assert_rejected(root, source, report)

    def test_invalid_source_paths_no_match_and_missing_source_are_denied(self):
        for filename in ("../id_token.hpp", "/id_token.hpp", "C:/id_token.hpp", "include\\id_token.hpp",
                         "include/../id_token.hpp", "id_token\x00.hpp", "id_token\ud800.hpp",
                         "private-key.pem", "include/missing_token.hpp", "src/unrelated.cpp"):
            with self.subTest(filename=repr(filename)), tempfile.TemporaryDirectory() as tmp:
                root, source, report, _ = self.fixture(tmp)
                self.metadata(report, {"gcovr/format_version": "0.6", "files": [{"file": filename}]})
                self.assert_rejected(root, source, report)

    def test_key_source_extensions_cannot_be_mapped_as_coverage_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, name = self.fixture(tmp)
            (source / "private-key.pem").write_text("PUBLIC_SYNTHETIC_NON_CODE", encoding="utf-8")
            self.metadata(report, {"gcovr/format_version": "0.6", "files": [{"file": "private-key.pem"}]})
            (report / name).unlink()
            (report / detail_name("private-key.pem")).write_text("PUBLIC_SYNTHETIC_NON_CODE", encoding="utf-8")
            self.assert_rejected(root, source, report)

    def test_matching_page_in_nested_directory_or_uploaded_alone_is_denied(self):
        for nested in (False, True):
            with self.subTest(nested=nested), tempfile.TemporaryDirectory() as tmp:
                root, source, report, name = self.fixture(tmp)
                if nested:
                    (report / "nested").mkdir()
                    (report / name).rename(report / "nested" / name)
                    self.assert_rejected(root, source, report)
                else:
                    encrypt = Mock()
                    with self.assertRaisesRegex(ValueError, "credential-like report member"):
                        self.archive(root, source, [report / name], encrypt)
                    encrypt.assert_not_called()

    def link(self, path, real):
        path.rename(real)
        try:
            path.symlink_to(real, target_is_directory=real.is_dir())
        except NotImplementedError:
            self.skipTest("Host cannot create the required symlink fixture")
        except OSError as error:
            if error.errno in (errno.EPERM, errno.EACCES) or getattr(error, "winerror", None) in (5, 1314):
                self.skipTest("Host denies creation of the required symlink fixture")
            raise

    def test_symlink_source_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, _ = self.fixture(tmp)
            self.link(source / "include/synthetic/id_token.hpp", root / "outside.hpp")
            self.assert_rejected(root, source, report)

    def test_symlink_metadata_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, _ = self.fixture(tmp)
            self.link(report / "coverage.json", root / "outside.json")
            self.assertEqual(runner.generated_coverage_html_names(source, report), frozenset())
            self.assert_rejected(root, source, report)

    def test_symlink_index_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, _ = self.fixture(tmp)
            self.link(report / "coverage.html", root / "outside.html")
            self.assert_rejected(root, source, report, "linked report member")

    def test_symlink_detail_is_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, name = self.fixture(tmp)
            self.link(report / name, root / "outside.html")
            self.assert_rejected(root, source, report, "linked report member")

    def test_metadata_byte_and_record_bounds_fail_closed(self):
        for bound in ("GCOVR_METADATA_LIMIT", "GCOVR_SOURCE_LIMIT"):
            with self.subTest(bound=bound), tempfile.TemporaryDirectory() as tmp:
                root, source, report, _ = self.fixture(tmp)
                if bound == "GCOVR_SOURCE_LIMIT":
                    self.metadata(report, {"gcovr/format_version": "0.6",
                        "files": [{"file": "include/synthetic/id_token.hpp"}] * 2})
                with patch.object(runner, bound, 1):
                    self.assert_rejected(root, source, report)

    def test_archive_bytes_limit_remains_enforced(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(ci, "MAX_ARCHIVE", 1):
            root, source, report, _ = self.fixture(tmp)
            self.assert_rejected(root, source, report, "report archive limit")

    def test_archive_member_count_limit_remains_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, _ = self.fixture(tmp)
            ordinary = report / "coverage.html"
            with patch.object(Path, "rglob", return_value=[ordinary] * 20001):
                self.assert_rejected(root, source, report, "report archive limit")

    def test_source_parent_link_cannot_escape_materialized_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, _ = self.fixture(tmp)
            self.link(source / "include/synthetic", root / "outside-source")
            self.assert_rejected(root, source, report)

    def test_report_root_link_and_outside_root_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, _ = self.fixture(tmp)
            self.link(report, root / "outside-report")
            self.assert_rejected(root, source, report, "unsafe report root")
            self.assert_rejected(root, source, root / "outside-report", "unsafe report root")

    def test_generic_noncoverage_report_does_not_require_coverage_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, source, report, name = self.fixture(tmp)
            (report / name).unlink()
            (report / "coverage.json").unlink()
            calls = Mock()
            self.archive(root, source, [report], calls)
            calls.assert_called_once()


if __name__ == "__main__":
    unittest.main()
