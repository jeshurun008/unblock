from datetime import datetime, timezone

from git import Repo, InvalidGitRepositoryError

from .base import Scanner, Signal, Severity


class GitScanner(Scanner):
    name = "git_scanner"

    def scan(self, repo_path: str) -> list[Signal]:
        signals: list[Signal] = []

        try:
            repo = Repo(repo_path)
        except InvalidGitRepositoryError:
            signals.append(
                Signal(
                    scanner_name=self.name,
                    severity=Severity.WARNING,
                    description="not a git repository",
                    rule_id="git.not_a_repo",
                )
            )
            return signals

        # uncommitted changes
        dirty_files = [item.a_path for item in repo.index.diff(None)]
        dirty_files += [item.a_path for item in repo.index.diff("HEAD")]
        dirty_files = sorted(set(dirty_files))

        if dirty_files:
            # separate likely-vendored/dependency noise from real files
            noisy_markers = (".venv", "node_modules", "site-packages", "__pycache__", ".git/")
            real_files = [f for f in dirty_files if not any(m in f for m in noisy_markers)]
            noisy_files = [f for f in dirty_files if f not in real_files]

            if noisy_files:
                description = (
                    f"{len(dirty_files)} uncommitted file(s) "
                    f"({len(real_files)} real, {len(noisy_files)} look vendored — "
                    f"check .gitignore for {noisy_markers[0]} etc.)"
                )
            else:
                shown = ", ".join(dirty_files[:5])
                more = f" (+{len(dirty_files) - 5} more)" if len(dirty_files) > 5 else ""
                description = f"{len(dirty_files)} uncommitted file(s): {shown}{more}"

            signals.append(
                Signal(
                    scanner_name=self.name,
                    severity=Severity.WARNING,
                    description=description,
                    rule_id="git.uncommitted_changes",
                    safe_to_autofix=False,
                    location="\n".join(f"      {f}" for f in real_files[:10]) or None,
                )
            )

            if noisy_files:
                # Zero-risk autofix: vendored/derived files keep getting tracked
                # because .gitignore doesn't cover them. Suggest adding the marker
                # dirs so they stop appearing as dirty. Safe to auto-apply.
                markers = sorted({m for m in noisy_markers if any(m in f for f in noisy_files)})
                signals.append(
                    Signal(
                        scanner_name=self.name,
                        severity=Severity.WARNING,
                        description=(
                            f"tracked vendored/derived files found ({len(noisy_files)}) — "
                            f"recommend adding to .gitignore: {', '.join(markers)}"
                        ),
                        rule_id="git.vendored_in_gitignore",
                        safe_to_autofix=True,
                        location="\n".join(f"      +{m}" for m in markers),
                    )
                )

        # last commit recency
        try:
            last_commit = next(repo.iter_commits(max_count=1))
            commit_dt = datetime.fromtimestamp(last_commit.committed_date, tz=timezone.utc)
            days_stale = (datetime.now(timezone.utc) - commit_dt).days

            if days_stale >= 10:
                signals.append(
                    Signal(
                        scanner_name=self.name,
                        severity=Severity.WARNING,
                        description=f"last commit {days_stale}d ago",
                        rule_id="git.stale_commit",
                    )
                )
            else:
                signals.append(
                    Signal(
                        scanner_name=self.name,
                        severity=Severity.INFO,
                        description=f"last commit {days_stale}d ago",
                        rule_id="git.recent_commit",
                    )
                )
        except StopIteration:
            signals.append(
                Signal(
                    scanner_name=self.name,
                    severity=Severity.WARNING,
                    description="no commits found",
                    rule_id="git.no_commits",
                )
            )

        return signals
