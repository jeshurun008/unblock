# unblock

A repo health agent. Scans your repos and tells you which one is actually blocked, and why.

Most tools tell you everything that's wrong. `unblock` tells you what to fix first — and it catches a specific class of bug most linters miss entirely: **auth-lifecycle gaps**. A JWT that gets issued but never refreshed doesn't throw an error in dev — it just silently logs users out in production, hours after the code that caused it. `unblock`'s signature scanner (`auth_flow_scanner`) uses AST-based static analysis, not regex, to catch exactly that.

## What it does
$ unblock scan
UNBLOCK
repo health agent — v0.1.0
Scanning 3 repo(s)...
Repo           Status    Top Signal
─────────────────────────────────────────────────────────
AssetFlow      blocked   token issued, no refresh handler found in this module
SOMA           stale     last commit 12d ago
Trackly        ok        CI passing
Fix this first: AssetFlow
Run unblock explain AssetFlow for detail

## Scanners

- **`git_scanner`** — uncommitted changes, commit recency, filters vendored/dependency noise (`.venv`, `node_modules`, etc.) so real findings aren't buried
- **`ci_scanner`** — GitHub Actions status (needs `GITHUB_TOKEN`)
- **`auth_flow_scanner`** — AST-based detection of JWT lifecycle bugs (PyJWT currently): tokens issued with no refresh path, `jwt.decode()` calls with no expiry-aware error handling

## Install

```bash
git clone <your-repo-url>
cd unblock
python -m venv venv
# Windows: .\venv\Scripts\Activate.ps1
# macOS/Linux: source venv/bin/activate
pip install -e .
```

## Usage

```bash
unblock init                    # create unblock.config.yaml
unblock add <path>               # register a repo
unblock scan                     # scan all configured repos
unblock scan --no-cache          # force a fresh scan, skip caching
unblock explain <repo>           # full breakdown + suggested fix
unblock list                     # show configured repos
```

## Architecture

Every scanner emits a `Signal` — a structured finding with severity, confidence, and location — never raw text. Detection is 100% deterministic (Python's `ast` module, not an LLM): scanners only report facts, keeping hallucination out of the detection layer entirely. Scan results are cached by a fingerprint of git HEAD + dirty-file state + scanner version, so an unchanged repo skips rescanning on the next run.

## Status

Early build. `git_scanner`, `ci_scanner`, and `auth_flow_scanner` (PyJWT) are working. JS/TS auth-flow detection, an LLM triage/explanation layer, and a risk-tiered `fix` command (auto-commit safe changes, open a PR for auth-critical ones) are next.
