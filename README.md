# Unblock

**A repository health CLI that helps developers find what is slowing a project down.**

Unblock inspects Git working-tree state, Python JWT lifecycle patterns, and (optionally) recent GitHub Actions runs. It combines deterministic scanners with an optional LLM-assisted scan for selected non-Python languages.

> Unblock is an early-stage developer tool. Findings are signals for human review, not a guarantee that a repository is secure or production-ready.

## What it checks

| Scanner | What it inspects | Network required |
|---|---|---:|
| Git | Tracked modifications, untracked files, likely vendored-file noise, and commit recency | No |
| Python auth | PyJWT issuance and expiry-exception patterns using Python's AST | No |
| CI | Recent GitHub Actions workflow runs for the repository's GitHub remote | Yes, with `GITHUB_TOKEN` |
| LLM auth | Narrow token-lifecycle patterns in JavaScript, TypeScript, Go, Java, and Ruby | Yes, with a supported provider key |

### Current limitations

- Python auth analysis is pattern-based and currently focuses on PyJWT `encode`/`decode` calls.
- A refresh handler in another module may not be visible to the Python scanner; review findings in context.
- The LLM scanner is optional and its output is always downgraded to warnings.
- The CI scanner checks the five most recent GitHub Actions workflow runs. Failed runs are blocking, in-progress runs are reported separately, and it does not inspect individual job logs.
- The cache tracks Git HEAD plus changed and untracked working-tree file contents. Scanner changes should bump `SCANNER_VERSION`.
- A scanner runtime error is reported as a warning and does not stop the remaining scanners.
- The Git scanner reports untracked files as uncommitted work; dependency folders are classified separately when detected.

## Install

Requires Python 3.10 or newer.

Clone the repository and install it in editable mode:

```bash
git clone https://github.com/jeshurun008/unblock.git
cd unblock
python -m pip install -e .
```

Optional LLM support:

```bash
python -m pip install -e ".[llm]"
```

## Quick start

Initialize a configuration file in the directory where you want to manage repositories:

```bash
unblock init
unblock add /absolute/path/to/your/project
unblock list
unblock scan
```

Scan one configured repository:

```bash
unblock scan my-project --no-cache
unblock explain my-project
```

Get machine-readable summary output:

```bash
unblock scan --json
```

For CI or scripts, return exit code `2` when any repository is classified as blocked:

```bash
unblock scan --fail-on-blocking
unblock scan --json --fail-on-blocking
```

Exit codes: `0` means the scan completed without a blocking status (unless strict mode is disabled), `1` means the command could not run (for example, no configured repository), and `2` means strict mode found at least one blocked repository. JSON output is pretty-printed and includes each scanner finding.

The configuration file is named `unblock.config.yaml`. It is local to your working directory and is intentionally excluded from version control.

## Optional integrations

### GitHub Actions status

Set a GitHub token with permission to read repository actions:

```bash
# macOS / Linux
export GITHUB_TOKEN="your-token"

# PowerShell
$env:GITHUB_TOKEN = "your-token"
```

The scanner discovers the GitHub repository from its Git remote. Without a token, it skips the remote CI check.

### LLM-assisted auth scan

Install the optional dependency and configure a provider key supported by the LLM pool. The LLM scanner only inspects selected source files and only emits warning-level findings; it never marks its own findings as safe to auto-fix.

## How findings are represented

Each scanner emits a structured signal with:

- **Severity** — `info`, `warning`, or `blocking`
- **Rule ID** — stable identifier suitable for filtering and automation
- **Location** — source path and line when available
- **Confidence** — scanner confidence where applicable
- **Safe-to-autofix** — explicit opt-in marker; false by default

The CLI groups findings into repository statuses:

- `ok` — no elevated score
- `stale` — warning-level score
- `blocked` — blocking-level score

Treat these statuses as triage hints, not objective quality scores.

## Development

```bash
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

Run the CLI locally:

```bash
python -m unblock.cli --help
```

## Project layout

```text
unblock/
├── unblock/
│   ├── scanners/       # Git, CI, Python AST, and optional LLM scanners
│   ├── output/         # Terminal presentation
│   ├── cache.py        # Working-tree-aware scan cache
│   ├── cli.py          # Typer commands
│   ├── config.py       # Local repository configuration
│   └── scoring.py      # Finding aggregation
├── tests/
└── pyproject.toml
```

## Roadmap

- [x] Git working-tree and commit-recency checks
- [x] Python AST-based PyJWT pattern checks
- [x] Optional GitHub Actions status lookup
- [x] Optional LLM-assisted checks for selected languages
- [x] Cache invalidation for untracked and modified files
- [x] Add regression coverage for Python JWT expiry-handler scope and scanner findings
- [x] Add Git scanner tests for clean, dirty, untracked, vendored, and unborn repositories
- [x] Include scanner findings in JSON output and add `--fail-on-blocking`
- [x] Add scanner-level tests for GitHub Actions CI behavior, including missing credentials, pending runs, failures, and provider errors
- [ ] Add a terminal demo and prepare a tagged release

## License

MIT
