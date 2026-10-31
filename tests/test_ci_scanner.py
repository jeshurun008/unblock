import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from git import Repo

from unblock.scanners.base import Severity
from unblock.scanners.ci_scanner import CIScanner


class CIScannerTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.repo = Repo.init(self.root)
        with self.repo.config_writer() as writer:
            writer.set_value("user", "name", "Unblock Tests")
            writer.set_value("user", "email", "tests@example.invalid")
        self.repo.create_remote("origin", "https://github.com/example/project.git")

    def tearDown(self):
        self.temp_dir.cleanup()

    def scan(self):
        return CIScanner().scan(str(self.root))

    def test_missing_token_skips_remote_check(self):
        with patch.dict(os.environ, {}, clear=True):
            findings = self.scan()
        self.assertEqual(findings[0].rule_id, "ci.no_token")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_missing_github_remote_skips_check(self):
        empty = tempfile.TemporaryDirectory()
        try:
            Repo.init(empty.name)
            with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
                findings = CIScanner().scan(empty.name)
            self.assertEqual(findings[0].rule_id, "ci.no_remote")
        finally:
            empty.cleanup()

    def run_with_conclusions(self, conclusions):
        runs = [
            types.SimpleNamespace(conclusion=value)
            for value in conclusions
        ]
        fake_repo = types.SimpleNamespace(
            get_workflow_runs=lambda: runs
        )
        fake_github = types.SimpleNamespace(
            Github=lambda token: types.SimpleNamespace(
                get_repo=lambda slug: fake_repo
            )
        )
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
            with patch.dict("sys.modules", {"github": fake_github}):
                return self.scan()

    def test_recent_successful_runs_are_passing(self):
        findings = self.run_with_conclusions(["success", "success", "success"])
        self.assertEqual(findings[0].rule_id, "ci.passing")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_any_recent_failure_is_blocking(self):
        findings = self.run_with_conclusions(["success", "failure", "success"])
        self.assertEqual(findings[0].rule_id, "ci.failing_runs")
        self.assertEqual(findings[0].severity, Severity.BLOCKING)
        self.assertIn("1 of last 3", findings[0].description)

    def test_no_workflow_runs_is_not_configured(self):
        findings = self.run_with_conclusions([])
        self.assertEqual(findings[0].rule_id, "ci.not_configured")
        self.assertEqual(findings[0].severity, Severity.INFO)

    def test_provider_exception_is_reported_as_fetch_error(self):
        fake_github = types.SimpleNamespace(
            Github=lambda token: types.SimpleNamespace(
                get_repo=lambda slug: (_ for _ in ()).throw(RuntimeError("API unavailable"))
            )
        )
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test-token"}):
            with patch.dict("sys.modules", {"github": fake_github}):
                findings = self.scan()
        self.assertEqual(findings[0].rule_id, "ci.fetch_error")
        self.assertIn("API unavailable", findings[0].description)


if __name__ == "__main__":
    unittest.main()
