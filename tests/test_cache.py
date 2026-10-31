import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from git import Repo

from unblock import cache
from unblock.scanners.base import Severity, Signal


class CacheFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.repo_path = Path(self.temp_dir.name)
        self.repo = Repo.init(self.repo_path)
        self.repo.config_writer().set_value("user", "name", "Unblock Tests").release()
        self.repo.config_writer().set_value("user", "email", "tests@example.invalid").release()
        tracked = self.repo_path / "tracked.py"
        tracked.write_text("value = 1\n", encoding="utf-8")
        self.repo.index.add(["tracked.py"])
        self.repo.index.commit("initial")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_untracked_file_changes_fingerprint(self):
        before = cache._fingerprint(str(self.repo_path))
        (self.repo_path / "new_module.py").write_text("token = 'first'\n", encoding="utf-8")
        after = cache._fingerprint(str(self.repo_path))
        self.assertNotEqual(before, after)

    def test_untracked_file_content_changes_fingerprint(self):
        module = self.repo_path / "new_module.py"
        module.write_text("token = 'first'\n", encoding="utf-8")
        before = cache._fingerprint(str(self.repo_path))
        module.write_text("token = 'second'\n", encoding="utf-8")
        after = cache._fingerprint(str(self.repo_path))
        self.assertNotEqual(before, after)

    def test_tracked_file_content_changes_fingerprint(self):
        before = cache._fingerprint(str(self.repo_path))
        (self.repo_path / "tracked.py").write_text("value = 2\n", encoding="utf-8")
        after = cache._fingerprint(str(self.repo_path))
        self.assertNotEqual(before, after)

    def test_cache_round_trip(self):
        signal = Signal(
            scanner_name="test_scanner",
            severity=Severity.WARNING,
            description="example finding",
            rule_id="test.example",
            location="sample.py:3",
            confidence=0.8,
        )
        # Keep the cache outside the scanned repository: creating cache files
        # inside the repo would itself appear as an untracked change and alter
        # the fingerprint between save and load.
        with tempfile.TemporaryDirectory() as cache_dir:
            with patch.object(cache, "CACHE_DIR", Path(cache_dir)):
                cache.save_cache(str(self.repo_path), [signal])
                restored = cache.load_cached(str(self.repo_path))
        self.assertEqual(len(restored), 1)
        self.assertEqual(restored[0].rule_id, "test.example")
        self.assertEqual(restored[0].severity, Severity.WARNING)
        self.assertEqual(restored[0].confidence, 0.8)


if __name__ == "__main__":
    unittest.main()
