"""0.5.2 reuses only the exact successful 0.5.1 package-cache producers."""
import copy
from pathlib import Path
import tempfile
import zipfile
import unittest
from unittest import mock

from secure_release import cef_cache as cache, cef_boringssl_isolation as isolation


class PreviousReleaseCacheTests(unittest.TestCase):
    def selection(self, platform):
        record = cache.RELEASE_051_BINARY_CACHES[platform]
        return {key: record[key] for key in
                ("run", "attempt", "artifact_id", "artifact_sha256")}

    def test_original_recipient_context_and_image_on_both_platforms(self):
        for platform, record in cache.RELEASE_051_BINARY_CACHES.items():
            selected = self.selection(platform)
            self.assertEqual(cache.selected_revision(selected, platform, "vcpkg-binaries", "a" * 40),
                             record["revision"])
            self.assertEqual(cache.binary_cache_image(selected, platform, "a" * 40), record["image"])
            with self.assertRaises(ValueError):
                cache.selected_revision(selected, platform, "cef-checkpoint", "a" * 40)
            for field in ("attempt", "artifact_id", "artifact_sha256"):
                changed = copy.deepcopy(selected)
                changed[field] = "0" * 64 if field == "artifact_sha256" else selected[field] + 1
                with self.subTest(platform=platform, field=field), self.assertRaises(ValueError):
                    cache.selected_revision(changed, platform, "vcpkg-binaries", "a" * 40)

    def test_failed_or_rerun_producer_is_rejected_before_download(self):
        for platform, record in cache.RELEASE_051_BINARY_CACHES.items():
            for status, conclusion, attempt in (("in_progress", None, 1),
                                                 ("completed", "failure", 1),
                                                 ("completed", "success", 2)):
                api = mock.Mock()
                api.get.return_value = {"path": ".github/workflows/build-combined-release.yml",
                                        "status": status, "conclusion": conclusion,
                                        "head_sha": record["revision"], "run_attempt": attempt}
                with mock.patch.object(cache, "check_run"), self.assertRaises(ValueError):
                    from pathlib import Path
                    cache.fetch(api, self.selection(platform), Path("/nonexistent-release-052-cache"),
                                platform=platform, kind="vcpkg-binaries", key="a" * 64,
                                revision="b" * 40, private="disposable")
                api.download.assert_not_called()


class CandidatePackageContinuationTests(unittest.TestCase):
    platform = "linux"
    record = cache.RELEASE_052_LINUX_PACKAGE_CONTINUATION

    def selection(self):
        return {key: self.record[key] for key in
                ("run", "attempt", "artifact_id", "artifact_sha256")}

    def test_only_exact_platform_packages_not_checkpoint_or_other_platform_are_admitted(self):
        record = self.record
        selected = self.selection()
        self.assertEqual(cache.selected_revision(selected, self.platform, "vcpkg-binaries", "a" * 40), record["revision"])
        self.assertEqual(cache.binary_cache_image(selected, self.platform, "a" * 40), record["image"])
        other_platform = "windows" if self.platform == "linux" else "linux"
        for platform, kind in ((other_platform, "vcpkg-binaries"), (self.platform, "cef-checkpoint")):
            with self.assertRaises(ValueError):
                cache.selected_revision(selected, platform, kind, "a" * 40)
        for key in ("attempt", "artifact_id", "artifact_sha256"):
            altered = dict(selected)
            altered[key] = "0" * 64 if key == "artifact_sha256" else selected[key] + 1
            with self.assertRaises(ValueError):
                cache.selected_revision(altered, self.platform, "vcpkg-binaries", "a" * 40)

    def test_failed_candidate_reuses_only_authenticated_packages_with_original_context(self):
        record = self.record
        api = mock.Mock()
        producer = {"path": ".github/workflows/build-combined-release.yml", "status": "completed",
                    "conclusion": "failure", "run_attempt": 1, "head_sha": record["revision"]}
        api.get.return_value = producer
        api.artifacts.return_value = [{"id": record["artifact_id"], "name": f'vcpkg-binaries-{self.platform}-{record["run"]}-1',
            "expired": False, "digest": "sha256:" + record["artifact_sha256"],
            "workflow_run": {"id": record["run"], "head_sha": record["revision"]}}]
        def download(endpoint, target, digest, **kwargs):
            self.assertEqual(digest, record["artifact_sha256"])
            with zipfile.ZipFile(target, "w") as archive:
                archive.writestr("index.enc", b"synthetic transport; crypto independently tested")
        api.download.side_effect = download
        def unseal(source, target, private, context):
            self.assertEqual(context["builder_sha"], record["revision"])
            self.assertEqual(context["platform"], self.platform)
            self.assertEqual(context["kind"], "vcpkg-binaries")
            target.mkdir()
            return {"fixture": True}
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(cache, "check_run"), \
                mock.patch.object(cache, "unseal", side_effect=unseal):
            result = cache.fetch(api, self.selection(), Path(folder) / "restored", platform=self.platform,
                                 kind="vcpkg-binaries", key="a" * 64, revision="b" * 40, private="fixture")
            self.assertEqual(result, {"fixture": True})
            for changed in ({"run_attempt": 2}, {"status": "in_progress"}, {"head_sha": "0" * 40},
                            {"conclusion": "success"}, {"conclusion": "cancelled"}):
                api.get.return_value = dict(producer, **changed)
                api.download.reset_mock()
                with self.assertRaises(ValueError):
                    cache.fetch(api, self.selection(), Path(folder) / "refused", platform=self.platform,
                                kind="vcpkg-binaries", key="a" * 64, revision="b" * 40, private="fixture")
                api.download.assert_not_called()


class WindowsCandidatePackageContinuationTests(CandidatePackageContinuationTests):
    platform = "windows"
    record = cache.RELEASE_052_WINDOWS_PACKAGE_CONTINUATION


class LatestLinuxCandidatePackageContinuationTests(CandidatePackageContinuationTests):
    record = cache.RELEASE_052_LINUX_NATIVE_PACKAGE_CONTINUATION


class RC4LinuxPackageContinuationTests(CandidatePackageContinuationTests):
    record = cache.RELEASE_052_RC4_PACKAGE_CACHES["linux"]


class RC4WindowsPackageContinuationTests(CandidatePackageContinuationTests):
    platform = "windows"
    record = cache.RELEASE_052_RC4_PACKAGE_CACHES["windows"]


class RC6LinuxPackageContinuationTests(CandidatePackageContinuationTests):
    record = cache.RELEASE_052_RC6_PACKAGE_CACHES["linux"]


class RC6WindowsPackageContinuationTests(CandidatePackageContinuationTests):
    platform = "windows"
    record = cache.RELEASE_052_RC6_PACKAGE_CACHES["windows"]


class FullCodecProviderTests(unittest.TestCase):
    def test_complete_provider_ownership_and_bytes_survive_relocation(self):
        with tempfile.TemporaryDirectory() as folder:
            installed = Path(folder) / "installed"
            prefix = installed / isolation.TRIPLET
            info = installed / "vcpkg/info"
            info.mkdir(parents=True)
            specs = [("ffmpeg", isolation.FFMPEG_VERSION, isolation.FFMPEG_PORT_VERSION,
                      isolation.FFMPEG_ARCHIVES)] + [(name, version, revision,
                      (archive, *isolation.FFMPEG_CODEC_COMPANIONS.get(name, ())))
                      for name, version, revision, archive in isolation.FFMPEG_CODEC_PROVIDERS]
            statuses = []
            for name, version, revision, archives in specs:
                statuses.append(f"Package: {name}\nVersion: {version}\nPort-Version: {revision}\n"
                                f"Architecture: {isolation.TRIPLET}\nStatus: install ok installed\n")
                listing = info / (name + "_" + version + "_" + isolation.TRIPLET + ".list")
                listing.write_text("".join(isolation.TRIPLET + "/" + archive + "\n" for archive in archives))
                for archive in archives:
                    path = prefix / archive
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"!<arch>\n")
            status = installed / "vcpkg/status"
            status.write_text("\n".join(statuses))
            receipt, providers = isolation._ffmpeg_runtime(installed, prefix)
            self.assertEqual(len(providers), len(isolation.FFMPEG_ARCHIVES) + len(isolation.FFMPEG_CODEC_PROVIDERS)
                             + sum(map(len, isolation.FFMPEG_CODEC_COMPANIONS.values())))
            self.assertEqual(set(receipt["codec_ownership"]), {spec[0] for spec in isolation.FFMPEG_CODEC_PROVIDERS})
            status.unlink()
            moved = Path(folder) / "relocated-installed"
            installed.rename(moved)
            installed, prefix = moved, moved / isolation.TRIPLET
            self.assertEqual(isolation._ffmpeg_runtime(installed, prefix, expected=receipt, require_status=False)[0], receipt)
            companion = prefix / isolation.FFMPEG_CODEC_COMPANIONS["libwebp"][1]
            original = companion.read_bytes()
            companion.write_bytes(original + b"tamper")
            with self.assertRaises(ValueError):
                isolation._ffmpeg_runtime(installed, prefix, expected=receipt, require_status=False)
            companion.write_bytes(original)
            path = prefix / isolation.FFMPEG_CODEC_PROVIDERS[0][3]
            path.write_bytes(b"!<arch>\nchanged")
            with self.assertRaises(ValueError):
                isolation._ffmpeg_runtime(installed, prefix, expected=receipt, require_status=False)


if __name__ == "__main__":
    unittest.main()
