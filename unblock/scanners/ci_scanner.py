import os
import re

from git import Repo, InvalidGitRepositoryError

from .base import Scanner, Signal, Severity

GITHUB_REMOTE_RE = re.compile(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$")


class CIScanner(Scanner):
    name = "ci_scanner"

    def _find_github_slug(self, repo_path: str) -> str | None:
        try:
            repo = Repo(repo_path)
        except InvalidGitRepositoryError:
            return None

        for remote in repo.remotes:
            for url in remote.urls:
                match = GITHUB_REMOTE_RE.search(url)
                if match:
                    return f"{match.group('owner')}/{match.group('repo')}"
        return None

    def scan(self, repo_path: str) -> list[Signal]:
        slug = self._find_github_slug(repo_path)

        if not slug:
            return [
                Signal(
                    scanner_name=self.name,
                    severity=Severity.INFO,
                    description="no github remote found, skipping CI check",
                    rule_id="ci.no_remote",
                )
            ]

        token = os.environ.get("GITHUB_TOKEN")
        if not token:
            return [
                Signal(
                    scanner_name=self.name,
                    severity=Severity.INFO,
                    description="GITHUB_TOKEN not set, skipping CI check",
                    rule_id="ci.no_token",
                )
            ]

        try:
            from github import Github

            gh = Github(token)
            gh_repo = gh.get_repo(slug)
            runs = gh_repo.get_workflow_runs()
            recent = list(runs[:5])

            if not recent:
                return [
                    Signal(
                        scanner_name=self.name,
                        severity=Severity.INFO,
                        description="no CI configured",
                        rule_id="ci.not_configured",
                    )
                ]

            failing = [r for r in recent if r.conclusion in ("failure", "cancelled", "timed_out", "action_required")]

            if failing:
                return [
                    Signal(
                        scanner_name=self.name,
                        severity=Severity.BLOCKING,
                        description=f"{len(failing)} of last {len(recent)} runs failing",
                        rule_id="ci.failing_runs",
                    )
                ]

            return [
                Signal(
                    scanner_name=self.name,
                    severity=Severity.INFO,
                    description="CI passing",
                    rule_id="ci.passing",
                )
            ]

        except Exception as e:
            return [
                Signal(
                    scanner_name=self.name,
                    severity=Severity.INFO,
                    description=f"could not fetch CI status: {e}",
                    rule_id="ci.fetch_error",
                )
            ]
