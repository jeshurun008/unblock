import hashlib
import json
import os
from pathlib import Path

from git import Repo, InvalidGitRepositoryError

from .scanners.base import Signal, Severity

SCANNER_VERSION = "1.0"  # bump this whenever scanner detection logic changes
CACHE_DIR = Path.home() / ".unblock" / "cache"


def _fingerprint(repo_path: str) -> str:
    """Combines git HEAD, dirty-file mtimes, and scanner version into one hash.
    Any change to the repo's committed OR uncommitted state invalidates the cache."""
    parts = [SCANNER_VERSION]

    try:
        repo = Repo(repo_path)
        try:
            parts.append(repo.head.commit.hexsha)
        except (ValueError, TypeError):
            parts.append("no-commits")

        dirty_files = sorted(set(
            [item.a_path for item in repo.index.diff(None)]
            + [item.a_path for item in repo.index.diff("HEAD")]
        ))
        for f in dirty_files:
            full_path = os.path.join(repo_path, f)
            if os.path.exists(full_path):
                parts.append(f"{f}:{os.path.getmtime(full_path)}")
    except InvalidGitRepositoryError:
        parts.append("not-a-repo")

    combined = "|".join(parts)
    return hashlib.sha256(combined.encode()).hexdigest()


def _cache_file(repo_path: str) -> Path:
    key = hashlib.sha256(os.path.abspath(repo_path).encode()).hexdigest()[:16]
    return CACHE_DIR / f"{key}.json"


def load_cached(repo_path: str) -> list[Signal] | None:
    cache_file = _cache_file(repo_path)
    if not cache_file.exists():
        return None

    try:
        with open(cache_file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    if data.get("fingerprint") != _fingerprint(repo_path):
        return None

    signals = []
    for s in data["signals"]:
        signals.append(
            Signal(
                scanner_name=s["scanner_name"],
                severity=Severity(s["severity"]),
                description=s["description"],
                rule_id=s["rule_id"],
                location=s.get("location"),
                safe_to_autofix=s.get("safe_to_autofix", False),
                confidence=s.get("confidence", 1.0),
            )
        )
    return signals


def save_cache(repo_path: str, signals: list[Signal]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_file = _cache_file(repo_path)
    data = {
        "fingerprint": _fingerprint(repo_path),
        "signals": [s.to_dict() for s in signals],
    }
    with open(cache_file, "w") as f:
        json.dump(data, f)
