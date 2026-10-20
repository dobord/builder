"""0.5.2 reuses only the exact successful 0.5.1 package-cache producers."""
import copy
from pathlib import Path
import tempfile
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


class FullCodecProviderTests(unittest.TestCase):
    def test_complete_provider_ownership_and_bytes_survive_relocation(self):
        with tempfile.TemporaryDirectory() as folder:
            installed = Path(folder) / "installed"
            prefix = installed / isolation.TRIPLET
            info = installed / "vcpkg/info"
            info.mkdir(parents=True)
            specs = [("ffmpeg", isolation.FFMPEG_VERSION, isolation.FFMPEG_PORT_VERSION,
                      isolation.FFMPEG_ARCHIVES)] + [(name, version, revision, (archive,))
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
            self.assertEqual(len(providers), len(isolation.FFMPEG_ARCHIVES) + len(isolation.FFMPEG_CODEC_PROVIDERS))
            self.assertEqual(set(receipt["codec_ownership"]), {spec[0] for spec in isolation.FFMPEG_CODEC_PROVIDERS})
            status.unlink()
            moved = Path(folder) / "relocated-installed"
            installed.rename(moved)
            installed, prefix = moved, moved / isolation.TRIPLET
            self.assertEqual(isolation._ffmpeg_runtime(installed, prefix, expected=receipt, require_status=False)[0], receipt)
            path = prefix / isolation.FFMPEG_CODEC_PROVIDERS[0][3]
            path.write_bytes(b"!<arch>\nchanged")
            with self.assertRaises(ValueError):
                isolation._ffmpeg_runtime(installed, prefix, expected=receipt, require_status=False)


if __name__ == "__main__":
    unittest.main()
