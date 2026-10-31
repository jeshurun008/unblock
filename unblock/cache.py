import hashlib
import json
import os
from pathlib import Path

from git import Repo, InvalidGitRepositoryError
from git.exc import BadName

from .scanners.base import Signal, Severity

SCANNER_VERSION = "1.1"  # bump whenever scanner detection or cache inputs change
CACHE_DIR = Path.home() / ".unblock" / "cache"


def _fingerprint(repo_path: str) -> str:
    """Fingerprint committed state plus tracked and untracked working-tree files.

    Hash file contents rather than mtimes so rapid edits, timestamp-preserving
    copies, and newly-created untracked source files all invalidate the cache.
    """
    parts = [SCANNER_VERSION]

    try:
        repo = Repo(repo_path)
        try:
            parts.append(repo.head.commit.hexsha)
        except (ValueError, TypeError):
            parts.append("no-commits")

        changed = {item.a_path for item in repo.index.diff(None) if item.a_path}
        try:
            changed.update(item.a_path for item in repo.index.diff("HEAD") if item.a_path)
        except (BadName, ValueError):
            # An initialized repository may not have a HEAD until its first commit.
            pass
        changed.update(repo.untracked_files)

        for relative_path in sorted(changed):
            full_path = Path(repo_path) / relative_path
            if not full_path.is_file():
                parts.append(f"{relative_path}:<missing>")
                continue
            digest = hashlib.sha256()
            try:
                with full_path.open("rb") as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        digest.update(chunk)
            except OSError:
                parts.append(f"{relative_path}:<unreadable>")
                continue
            parts.append(f"{relative_path}:{digest.hexdigest()}")
    except InvalidGitRepositoryError:
        parts.append("not-a-repo")

    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _cache_file(repo_path: str) -> Path:
    key = hashlib.sha256(os.path.abspath(repo_path).encode()).hexdigest()[:16]
    return CACHE_DIR / f"{key}.json"


def load_cached(repo_path: str) -> list[Signal] | None:
    cache_file = _cache_file(repo_path)
    if not cache_file.exists():
        return None

    try:
        with cache_file.open(encoding="utf-8") as source:
            data = json.load(source)
        if data.get("fingerprint") != _fingerprint(repo_path):
            return None

        return [
            Signal(
                scanner_name=item["scanner_name"],
                severity=Severity(item["severity"]),
                description=item["description"],
                rule_id=item["rule_id"],
                location=item.get("location"),
                safe_to_autofix=item.get("safe_to_autofix", False),
                confidence=item.get("confidence", 1.0),
            )
            for item in data["signals"]
        ]
    except (json.JSONDecodeError, OSError, KeyError, TypeError, ValueError):
        return None


def save_cache(repo_path: str, signals: list[Signal]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_file(repo_path)
    data = {
        "fingerprint": _fingerprint(repo_path),
        "signals": [signal.to_dict() for signal in signals],
    }
    temporary_file = cache_file.with_suffix(".tmp")
    with temporary_file.open("w", encoding="utf-8") as target:
        json.dump(data, target)
    temporary_file.replace(cache_file)
