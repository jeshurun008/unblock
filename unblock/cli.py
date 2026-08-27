from pathlib import Path
from .scanners.llm_auth_scanner import LLMAuthScanner

import typer
from rich.console import Console
from rich.table import Table
from rich import box
from rich.panel import Panel
import typer.rich_utils as rich_utils

from . import config as cfg
from . import cache as cache_mod
from .output.banner import print_banner
from .scanners.git_scanner import GitScanner
from .scanners.ci_scanner import CIScanner
from .scanners.auth_flow_scanner import AuthFlowScanner
from .scanners.base import Severity
from .scoring import score, status, top_signal

# recolor typer's --help rendering to the blue-only palette
rich_utils.STYLE_OPTION = "bold #3B82F6"
rich_utils.STYLE_SWITCH = "bold #3B82F6"
rich_utils.STYLE_USAGE = "bold #1E3A8A"
rich_utils.STYLE_USAGE_COMMAND = "bold #3B82F6"
rich_utils.STYLE_HELPTEXT_FIRST_LINE = "bold white"
rich_utils.STYLE_HELPTEXT = "dim white"
rich_utils.STYLE_OPTION_DEFAULT = "dim #1E3A8A"
rich_utils.STYLE_REQUIRED_SHORT = "bold #3B82F6"
rich_utils.STYLE_REQUIRED_LONG = "dim #3B82F6"
rich_utils.STYLE_OPTIONS_PANEL_BORDER = "#1E3A8A"
rich_utils.STYLE_COMMANDS_PANEL_BORDER = "#1E3A8A"
rich_utils.STYLE_ERRORS_PANEL_BORDER = "bold #3B82F6"
rich_utils.STYLE_OPTIONS_TABLE_LEADING = 0
rich_utils.STYLE_COMMANDS_TABLE_SHOW_LINES = False

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help="[bold #3B82F6]unblock[/bold #3B82F6] — repo health agent. Scans your repos and tells you which one is actually blocked, and why.",
    epilog="[dim #1E3A8A]Run [bold #3B82F6]unblock <command> --help[/bold #3B82F6] for details on any command.[/dim #1E3A8A]",
)
console = Console(width=110)

SCANNERS = [GitScanner(), CIScanner(), AuthFlowScanner(), LLMAuthScanner()]

@app.command()
def init():
    """Create default unblock.config.yaml in current dir."""
    path = cfg.init_config()
    console.print(f"  created {path}")


@app.command()
def add(path: str):
    """Add a repo to config."""
    repo_path = Path(path).expanduser().resolve()
    if not repo_path.exists():
        console.print(f"  path does not exist: {repo_path}")
        raise typer.Exit(1)
    name = repo_path.name
    cfg.add_repo(name, str(repo_path))
    console.print(f"  added {name} -> {repo_path}")


@app.command()
def remove(name: str):
    """Remove a repo from config."""
    removed = cfg.remove_repo(name)
    if removed:
        console.print(f"  removed {name}")
    else:
        console.print(f"  no repo named {name} found")


@app.command(name="list")
def list_repos():
    """Show configured repos without scanning."""
    data = cfg.load_config()
    repos = data["repos"]
    if not repos:
        console.print("  no repos configured. run `unblock add <path>` first.")
        return
    console.print(f"  configured repos ({len(repos)})\n")
    for r in repos:
        console.print(f"  {r['name']:<24}{r['path']}")


def _run_scanners(repo_path: str, verbose: bool = True, use_cache: bool = True):
    if use_cache:
        cached = cache_mod.load_cached(repo_path)
        if cached is not None:
            if verbose:
                console.print("    ✓ cache hit — skipping rescan (unchanged since last run)")
            return cached

    all_signals = []
    for scanner in SCANNERS:
        if verbose:
            console.print(f"    → [#1E3A8A]{scanner.name:<18}[/#1E3A8A] scanning...")
        signals = scanner.scan(repo_path)
        all_signals.extend(signals)
        if verbose:
            blocking = [s for s in signals if s.severity.value == "blocking"]
            mark = "[bold #3B82F6]✗[/bold #3B82F6]" if blocking else "[#1E3A8A]✓[/#1E3A8A]"
            top = top_signal(signals)
            summary = top.description if top else "no findings"
            console.print(f"    {mark} [#1E3A8A]{scanner.name:<18}[/#1E3A8A] {summary}")

    if use_cache:
        cache_mod.save_cache(repo_path, all_signals)

    return all_signals


@app.command()
def scan(
    repo: str = typer.Argument(None, help="scan a single repo by name"),
    json_out: bool = typer.Option(False, "--json", help="machine-readable output"),
    no_cache: bool = typer.Option(False, "--no-cache", help="force rescan, ignore cache"),
):
    """Scan all configured repos, or a single repo by name."""
    data = cfg.load_config()
    repos = data["repos"]
    if repo:
        repos = [r for r in repos if r["name"] == repo]
        if not repos:
            console.print(f"  no repo named {repo} found")
            raise typer.Exit(1)

    if not repos:
        console.print("  no repos configured. run `unblock add <path>` first.")
        raise typer.Exit(1)

    if not json_out:
        print_banner()
        console.print(f"  Scanning {len(repos)} repo(s)...\n")

    results = []
    for r in repos:
        if not json_out:
            console.print(f"  → {r['name']}")
        signals = _run_scanners(r["path"], verbose=not json_out, use_cache=not no_cache)
        s = score(signals)
        st = status(signals)
        top = top_signal(signals)
        results.append({"repo": r["name"], "status": st, "score": s, "signals": signals, "top": top})
        if not json_out:
            console.print(f"  ✓ {r['name']:<20} done — {st}\n")

    if json_out:
        import json as jsonlib

        out = [
            {"repo": r["repo"], "status": r["status"], "score": r["score"]}
            for r in results
        ]
        typer.echo(jsonlib.dumps(out))
        return

    table = Table(box=box.SIMPLE, show_header=True, header_style="bold #3B82F6", pad_edge=False, width=100)
    table.add_column("Repo", no_wrap=True, style="#1E3A8A")
    table.add_column("Status", no_wrap=True)
    table.add_column("Top Signal", overflow="ellipsis", no_wrap=True)

    status_style = {"blocked": "bold #3B82F6", "stale": "#1E3A8A", "ok": "dim #1E3A8A"}
    for r in results:
        top_desc = r["top"].description if r["top"] else "no findings"
        st_style = status_style.get(r["status"], "#1E3A8A")
        table.add_row(r["repo"], f"[{st_style}]{r['status']}[/{st_style}]", top_desc)

    console.print(table)

    blocked = [r for r in results if r["status"] == "blocked"]
    if blocked:
        worst = max(blocked, key=lambda r: r["score"])
        console.print(f"\n  [bold #3B82F6]Fix this first: {worst['repo']}[/bold #3B82F6]")
        console.print(f"  [#1E3A8A]Run `unblock explain {worst['repo']}` for detail[/#1E3A8A]")


@app.command()
def fix(
    repo: str = typer.Argument(..., help="repo to fix, by name"),
    no_cache: bool = typer.Option(False, "--no-cache", help="force rescan, ignore cache"),
):
    """Risk-tiered remediation: auto-commit safe fixes, flag auth-critical ones for a PR."""
    data = cfg.load_config()
    match = next((r for r in data["repos"] if r["name"] == repo), None)
    if not match:
        console.print(f"  no repo named {repo} found")
        raise typer.Exit(1)

    signals = _run_scanners(match["path"], verbose=True, use_cache=not no_cache)

    safe = [s for s in signals if s.safe_to_autofix]
    risky = [s for s in signals if s.severity == Severity.BLOCKING and not s.safe_to_autofix]

    console.print(f"\n  [bold #3B82F6]{repo}[/bold #3B82F6] — fix plan\n")

    if not safe:
        console.print("  no auto-fix candidates found (nothing marked safe_to_autofix)")
    else:
        try:
            from git import Repo as GitRepo, InvalidGitRepositoryError
            grepo = GitRepo(match["path"])
        except InvalidGitRepositoryError:
            console.print("  ✗ not a git repo — cannot auto-commit safe fixes")
            raise typer.Exit(1)

        gitignore_path = Path(match["path"]) / ".gitignore"
        additions = []
        for s in safe:
            if s.rule_id == "git.vendored_in_gitignore" and s.location:
                for line in s.location.splitlines():
                    line = line.strip()
                    if line.startswith("+") and len(line) > 1:
                        additions.append(line[1:].strip())
            template = [
                "unblock: ignore previously-tracked vendored/derived files",
                *[f"/{a}" for a in additions],
                "",
            ]
            console.print(f"    ✓ auto-fixing: {s.description}")

        applied = []
        if additions:
            existing = ""
            if gitignore_path.exists():
                existing = gitignore_path.read_text(encoding="utf-8")
            new_lines = [f"/{a}" for a in additions]
            # avoid duplicating entries that are already present
            to_add = [l for l in new_lines if l not in existing.splitlines()]
            if to_add:
                with open(gitignore_path, "a", encoding="utf-8") as f:
                    if existing and not existing.endswith("\n"):
                        f.write("\n")
                    f.write("\n".join([template[0], *to_add, ""]))
                try:
                    grepo.index.add([str(gitignore_path.relative_to(match["path"]))])
                    grepo.index.commit("unblock: ignore vendored/derived files")
                    applied = to_add
                except Exception as e:
                    console.print(f"    ✗ could not commit .gitignore: {e}")
            else:
                console.print("  [dim]already ignored — nothing to add[/dim]")

        console.print(f"  [dim]applied {len(applied)} ignore rule(s) and committed[/dim]" if applied
                      else "  [dim]no .gitignore changes applied[/dim]")

    if risky:
        console.print("\n  [#1E3A8A]auth-critical findings need a human review / PR — not auto-applied:[/#1E3A8A]")
        for s in risky:
            suggestion = RULE_SUGGESTIONS.get(s.rule_id, "Review this finding and address it before moving on.")
            console.print(f"    ✗ {s.rule_id}: {s.description}")
            console.print(f"      [dim #1E3A8A]{suggestion}[/dim #1E3A8A]")
    else:
        console.print("\n  no risky (blocking) findings — nothing requires a manual PR.")


RULE_SUGGESTIONS = {
    "auth_flow.no_refresh_handler": "Add a refresh/renew function in this module so tokens don't silently die mid-session in production.",
    "auth_flow.no_expiry_check": "Wrap this jwt.decode() call in a try/except catching jwt.ExpiredSignatureError so expiry fails loud, not silent.",
    "git.uncommitted_changes": "Commit or stash these files — uncommitted work doesn't show up for anyone else, including CI.",
    "git.stale_commit": "This repo hasn't moved in a while — worth a quick pass to confirm it's not silently blocked on something.",
    "ci.failing_runs": "CI is failing — fix this before anything else lands, a broken pipeline blocks every future merge.",
    "llm_auth.token-issuance-no-refresh": "Add a refresh/renewal path for this token so it doesn't silently die mid-session in production.",
    "llm_auth.token-verify-no-expiry-handling": "Add a distinct branch for the expired-token case so it isn't treated the same as an invalid/malformed one.",
}


@app.command()
def explain(repo: str):
    """Full breakdown for one repo: all scanner findings."""
    data = cfg.load_config()
    match = next((r for r in data["repos"] if r["name"] == repo), None)
    if not match:
        console.print(f"  no repo named {repo} found")
        raise typer.Exit(1)

    signals = []
    for scanner in SCANNERS:
        signals.extend(scanner.scan(match["path"]))

    st = status(signals)
    st_style = {"blocked": "bold #3B82F6", "stale": "#1E3A8A", "ok": "dim #1E3A8A"}.get(st, "#1E3A8A")
    console.print(f"\n  {repo} — [{st_style}]{st}[/{st_style}]\n")

    severity_style = {
        "blocking": "bold #3B82F6",
        "warning": "#1E3A8A",
        "info": "dim white",
    }
    severity_mark = {
        "blocking": "✗",
        "warning": "!",
        "info": "·",
    }

    by_scanner: dict[str, list] = {}
    for s in signals:
        by_scanner.setdefault(s.scanner_name, []).append(s)

    for scanner_name, sigs in by_scanner.items():
        console.print(f"  [bold #3B82F6]{scanner_name}[/bold #3B82F6]")
        for s in sigs:
            sev = s.severity.value
            style = severity_style.get(sev, "white")
            mark = severity_mark.get(sev, "-")
            conf = f"  [dim]confidence {s.confidence:.2f}[/dim]" if s.confidence < 1.0 else ""
            console.print(f"    [{style}]{mark}[/{style}] [{style}]{s.description}[/{style}]{conf}")
            if s.location:
                console.print(f"[dim #1E3A8A]{s.location}[/dim #1E3A8A]")
        console.print("")

    blocking_signals = [s for s in signals if s.severity.value == "blocking"]
    if blocking_signals:
        top = top_signal(blocking_signals)
        suggestion = RULE_SUGGESTIONS.get(top.rule_id, "Review this finding and address it before moving on.")
        panel_body = f"[bold #3B82F6]{top.description}[/bold #3B82F6]\n\n{suggestion}"
        console.print(
            Panel(
                panel_body,
                title="[bold #3B82F6]Suggested Fix[/bold #3B82F6]",
                border_style="#1E3A8A",
                width=100,
            )
        )
    elif signals:
        console.print(
            Panel(
                "No blocking issues found — this repo looks healthy.",
                title="[bold #3B82F6]Insight[/bold #3B82F6]",
                border_style="#1E3A8A",
                width=100,
            )
        )


if __name__ == "__main__":
    app()