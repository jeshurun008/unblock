import ast
import os

from .base import Scanner, Signal, Severity

VENDOR_DIRS = {".venv", "venv", "node_modules", "__pycache__", ".git", "site-packages"}

REFRESH_NAME_HINTS = ("refresh", "renew", "reissue", "rotate")

TEST_BASENAME_PREFIXES = ("test_",)
TEST_BASENAME_SUFFIX = "_test"


def _iter_python_files(repo_path: str):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in VENDOR_DIRS]
        for f in files:
            if f.endswith(".py"):
                yield os.path.join(root, f)


def _is_test_file(filepath: str, repo_path: str) -> bool:
    """Conservative test-file detection, based on the repo-relative path.

    A bare "test" substring anywhere is NOT enough (a folder/repo named
    `scantest` or `test-app` would otherwise mark every file in it as a test).
    Only file basenames and clear directory segments count.
    """
    rel = os.path.relpath(filepath, repo_path).replace("\\", "/").lower()
    basename = os.path.basename(rel)
    if basename.startswith(TEST_BASENAME_PREFIXES) or basename.endswith(TEST_BASENAME_SUFFIX):
        return True
    dirs = rel.split("/")[:-1]
    return any(d in ("tests", "test") for d in dirs)


def _jwt_import_names(tree: ast.AST) -> dict[str, set[str]]:
    """Map jwt attribute -> identifiers bound to it, e.g. {'encode': {'jwt', 'e'}, 'decode': {'jwt', 'j_decode'}}.

    Covers `import jwt`, `from jwt import encode`, `import jwt as j`, and
    `from jwt import encode as e`. A bare identifier only counts for the
    attribute it was actually imported as; `jwt.encode()` / `j.encode()`
    resolve to 'encode' on the jwt module.
    """
    names: dict[str, set[str]] = {"encode": set(), "decode": set()}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "jwt":
                    bound = alias.asname or "jwt"
                    names["encode"].add(bound)
                    names["decode"].add(bound)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "jwt":
                for alias in node.names:
                    bound = alias.asname or alias.name
                    if alias.name == "*":
                        names["encode"].add(bound)
                        names["decode"].add(bound)
                    elif alias.name in names:
                        names[alias.name].add(bound)
    return names


def _is_jwt_call(node: ast.AST, attr_name: str, jwt_names: dict[str, set[str]]) -> bool:
    """True if node is jwt.<attr>(...) or a bare identifier bound to that jwt attribute."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute):
        base = func.value
        if not (isinstance(base, ast.Name) and base.id in jwt_names[attr_name]):
            return False
        return func.attr == attr_name
    if isinstance(func, ast.Name):
        return func.id in jwt_names[attr_name]
    return False


def _walk_calls(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def _has_refresh_sibling(tree: ast.AST) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            name = node.name.lower()
            if any(hint in name for hint in REFRESH_NAME_HINTS):
                return True
    return False


def _exception_names(node: ast.AST) -> set[str]:
    """Collect exception names from Name, Attribute, or tuple expressions."""
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, ast.Attribute):
        return {node.attr}
    if isinstance(node, ast.Tuple):
        names: set[str] = set()
        for item in node.elts:
            names.update(_exception_names(item))
        return names
    return set()


def _handles_expiry(tree: ast.AST, decode_call: ast.AST) -> bool:
    """Return whether this decode call is protected by an expiry-specific except.

    The handler must belong to a try statement whose body contains this call,
    and it must be inside the call's nearest enclosing function. An unrelated
    handler elsewhere in the function (or in an outer function) is not enough.
    """
    parents = {
        child: node
        for node in ast.walk(tree)
        for child in ast.iter_child_nodes(node)
    }
    current = decode_call

    while current in parents:
        parent = parents[current]

        if isinstance(parent, ast.Try) and current in parent.body:
            for handler in parent.handlers:
                if handler.type is None:
                    continue
                if any("expired" in name.lower() for name in _exception_names(handler.type)):
                    return True

        # Do not let an outer function's exception handling cover a nested
        # function definition: the nested function executes independently.
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            return False

        current = parent

    return False


class AuthFlowScanner(Scanner):
    name = "auth_flow_scanner"

    def scan(self, repo_path: str) -> list[Signal]:
        signals: list[Signal] = []
        encode_sites: list[tuple[str, int]] = []
        decode_without_expiry: list[tuple[str, int]] = []
        any_jwt_usage = False

        for filepath in _iter_python_files(repo_path):
            try:
                # utf-8-sig strips a UTF-8 BOM (common on Windows) so BOM'd
                # files parse instead of being silently skipped.
                with open(filepath, "r", encoding="utf-8-sig", errors="ignore") as f:
                    source = f.read()
                tree = ast.parse(source, filename=filepath)
            except (SyntaxError, UnicodeDecodeError):
                continue

            jwt_names = _jwt_import_names(tree)
            if not jwt_names:
                continue

            file_has_encode = False
            for call in _walk_calls(tree):
                if _is_jwt_call(call, "encode", jwt_names):
                    any_jwt_usage = True
                    file_has_encode = True
                    encode_sites.append((filepath, call.lineno))
                if _is_jwt_call(call, "decode", jwt_names):
                    any_jwt_usage = True
                    if not _handles_expiry(tree, call):
                        decode_without_expiry.append((filepath, call.lineno))

            if file_has_encode and not _has_refresh_sibling(tree):
                rel = os.path.relpath(filepath, repo_path)
                # Real code: no refresh path is a blocker. Test/fixture files commonly
                # mint tokens with no refresh sibling on purpose — don't block on them.
                is_test = _is_test_file(filepath, repo_path)
                signals.append(
                    Signal(
                        scanner_name=self.name,
                        severity=Severity.WARNING if is_test else Severity.BLOCKING,
                        description=(
                            "token issued in test/fixture code, no refresh handler found in this module"
                            if is_test
                            else "token issued, no refresh handler found in this module"
                        ),
                        rule_id="auth_flow.no_refresh_handler",
                        location=f"      {rel}:{encode_sites[-1][1]}",
                        safe_to_autofix=False,
                    )
                )

        for filepath, lineno in decode_without_expiry:
            rel = os.path.relpath(filepath, repo_path)
            signals.append(
                Signal(
                    scanner_name=self.name,
                    severity=Severity.BLOCKING,
                    description="token verified with no ExpiredSignatureError handling",
                    rule_id="auth_flow.no_expiry_check",
                    location=f"      {rel}:{lineno}",
                    safe_to_autofix=False,
                )
            )

        if not any_jwt_usage:
            signals.append(
                Signal(
                    scanner_name=self.name,
                    severity=Severity.INFO,
                    description="no PyJWT usage found",
                    rule_id="auth_flow.not_applicable",
                )
            )

        return signals
