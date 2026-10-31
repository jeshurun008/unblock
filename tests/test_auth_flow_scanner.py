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
