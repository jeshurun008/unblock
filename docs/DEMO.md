# Unblock terminal walkthrough

This is an illustrative walkthrough. Repository names and findings are sample data; exact output depends on the repositories you scan.

## 1. Register repositories

```console
$ unblock init
created unblock.config.yaml

$ unblock add ~/code/api
added api -> /home/dev/code/api

$ unblock add ~/code/web
added web -> /home/dev/code/web
```

## 2. Scan everything

```console
$ unblock scan
Scanning 2 repo(s)...

→ api
  git_scanner       last commit 2d ago
  auth_flow_scanner JWT decode has no explicit expiry handler
  ci_scanner        CI passing

→ web
  git_scanner       3 uncommitted file(s)
  auth_flow_scanner no PyJWT usage detected
  ci_scanner        1 of last 5 runs failing
```

The summary groups repositories by triage status. A blocking authentication or CI finding should be reviewed before treating a repository as healthy.

## 3. Inspect one repository

```console
$ unblock explain api
```

Use the full findings view to inspect rule IDs, severity, confidence, and source locations before changing code.

## 4. Use JSON in automation

```console
$ unblock scan --json
```

For CI pipelines that should fail when any configured repository is blocked:

```console
$ unblock scan --json --fail-on-blocking
```

Strict mode exits with status code `2` when at least one repository is blocked. A command/configuration error exits with `1`.

## Safety notes

- Findings are triage signals, not proof that a repository is secure or insecure.
- Review source context before applying authentication changes.
- Unblock does not automatically rewrite authentication code.
- The optional LLM scanner emits warning-level findings only.
