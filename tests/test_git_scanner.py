import tempfile
import unittest
from pathlib import Path

from git import Repo

from unblock.scanners.base import Severity
from unblock.scanners.git_scanner import GitScanner


class GitScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def init_repo(self):
        repo = Repo.init(self.root)
        with repo.config_writer() as writer:
            writer.set_value("user", "name", "Unblock Tests")
            writer.set_value("user", "email", "tests@example.invalid")
        return repo

    def commit_file(self, repo, relative_path, content="value = 1\n"):
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        repo.index.add([relative_path])
        repo.index.commit(f"add {relative_path}")
        return target

    def scan(self):
        return GitScanner().scan(str(self.root))

    def test_non_git_directory_is_reported(self):
        findings = self.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "git.not_a_repo")
        self.assertEqual(findings[0].severity, Severity.WARNING)

    def test_untracked_file_is_reported(self):
        repo = self.init_repo()
        self.commit_file(repo, "tracked.py")
        (self.root / "new.py").write_text("print('new')\n", encoding="utf-8")
        findings = self.scan()
        dirty = next(item for item in findings if item.rule_id == "git.uncommitted_changes")
        self.assertIn("new.py", dirty.description)

    def test_modified_tracked_file_is_reported(self):
        repo = self.init_repo()
        target = self.commit_file(repo, "app.py")
        target.write_text("value = 2\n", encoding="utf-8")
        findings = self.scan()
        dirty = next(item for item in findings if item.rule_id == "git.uncommitted_changes")
        self.assertIn("app.py", dirty.description)

    def test_clean_repository_reports_recent_commit(self):
        repo = self.init_repo()
        self.commit_file(repo, "app.py")
        findings = self.scan()
        self.assertTrue(any(item.rule_id == "git.recent_commit" for item in findings))
        self.assertFalse(any(item.rule_id == "git.uncommitted_changes" for item in findings))

    def test_unborn_repository_does_not_crash(self):
        self.init_repo()
        findings = self.scan()
        self.assertTrue(any(item.rule_id == "git.no_commits" for item in findings))

    def test_tracked_dependency_changes_are_classified_as_vendored(self):
        repo = self.init_repo()
        target = self.commit_file(repo, "node_modules/example/index.js", "module.exports = 1\n")
        target.write_text("module.exports = 2\n", encoding="utf-8")
        findings = self.scan()
        vendored = next(item for item in findings if item.rule_id == "git.vendored_in_gitignore")
        self.assertTrue(vendored.safe_to_autofix)
        self.assertIn("node_modules", vendored.description)


if __name__ == "__main__":
    unittest.main()
