import ast
import unittest

from unblock.scanners.auth_flow_scanner import _handles_expiry


class AuthExpiryHandlingTests(unittest.TestCase):
    def _decode_call(self, source):
        tree = ast.parse(source)
        return tree, next(
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "decode"
        )

    def test_matching_expiry_handler_wraps_decode(self):
        tree, call = self._decode_call("""
import jwt

def verify(token):
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
""")
        self.assertTrue(_handles_expiry(tree, call))

    def test_unrelated_expiry_handler_does_not_cover_decode(self):
        tree, call = self._decode_call("""
import jwt

def verify(token):
    try:
        refresh_session()
    except jwt.ExpiredSignatureError:
        recover()
    return jwt.decode(token, SECRET, algorithms=["HS256"])
""")
        self.assertFalse(_handles_expiry(tree, call))

    def test_generic_exception_handler_is_not_expiry_specific(self):
        tree, call = self._decode_call("""
import jwt

def verify(token):
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except Exception:
        return None
""")
        self.assertFalse(_handles_expiry(tree, call))

    def test_outer_function_handler_does_not_cover_nested_function(self):
        tree, call = self._decode_call("""
import jwt

def outer():
    try:
        prepare()
    except jwt.ExpiredSignatureError:
        recover()

    def verify(token):
        return jwt.decode(token, SECRET, algorithms=["HS256"])
""")
        self.assertFalse(_handles_expiry(tree, call))

    def test_alias_in_tuple_handler_is_recognized(self):
        tree, call = self._decode_call("""
import jwt

def verify(token):
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, ValueError):
        return None
""")
        self.assertTrue(_handles_expiry(tree, call))


if __name__ == "__main__":
    unittest.main()

import tempfile
from pathlib import Path

from unblock.scanners.auth_flow_scanner import AuthFlowScanner
from unblock.scanners.base import Severity


class AuthFlowScannerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def write(self, relative_path, source):
        target = self.root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")

    def scan(self):
        return AuthFlowScanner().scan(str(self.root))

    def test_decode_without_expiry_handler_is_blocking(self):
        self.write("auth.py", '''
import jwt
def verify(token):
    return jwt.decode(token, SECRET, algorithms=["HS256"])
''')
        findings = self.scan()
        match = next(item for item in findings if item.rule_id == "auth_flow.no_expiry_check")
        self.assertEqual(match.severity, Severity.BLOCKING)
        self.assertIn("auth.py:", match.location)

    def test_decode_with_expiry_handler_is_not_flagged(self):
        self.write("auth.py", '''
import jwt
def verify(token):
    try:
        return jwt.decode(token, SECRET, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
''')
        findings = self.scan()
        self.assertFalse(any(item.rule_id == "auth_flow.no_expiry_check" for item in findings))

    def test_unrelated_expiry_handler_does_not_hide_decode_finding(self):
        self.write("auth.py", '''
import jwt
def verify(token):
    try:
        refresh_session()
    except jwt.ExpiredSignatureError:
        recover()
    return jwt.decode(token, SECRET, algorithms=["HS256"])
''')
        findings = self.scan()
        self.assertTrue(any(item.rule_id == "auth_flow.no_expiry_check" for item in findings))

    def test_token_issue_location_uses_its_own_file(self):
        self.write("a_issue.py", '''
import jwt
def issue():
    return jwt.encode({"sub": "a"}, SECRET, algorithm="HS256")
''')
        self.write("z_issue.py", '''
import jwt
def issue():
    return jwt.encode({"sub": "z"}, SECRET, algorithm="HS256")
''')
        findings = [item for item in self.scan() if item.rule_id == "auth_flow.no_refresh_handler"]
        locations = {item.location for item in findings}
        self.assertEqual(len(locations), 2)
        self.assertTrue(any("a_issue.py:" in item for item in locations))
        self.assertTrue(any("z_issue.py:" in item for item in locations))

    def test_no_pyjwt_usage_reports_not_applicable(self):
        self.write("plain.py", "def add(a, b):\\n    return a + b\\n")
        findings = self.scan()
        self.assertTrue(any(item.rule_id == "auth_flow.not_applicable" for item in findings))
