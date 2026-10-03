import ast
import unittest
from ast_security_scanner import SecurityVisitor

class TestASTSecurityScanner(unittest.TestCase):
    def _scan_code(self, code):
        tree = ast.parse(code)
        visitor = SecurityVisitor()
        visitor.visit(tree)
        return visitor.issues

    def test_bare_raise_allowed(self):
        code = """
try:
    do_something()
except Exception:
    raise
"""
        issues = self._scan_code(code)
        self.assertEqual(issues, [])

    def test_raise_from_none_allowed(self):
        code = """
try:
    do_something()
except Exception as e:
    raise CustomException("Failed") from None
"""
        issues = self._scan_code(code)
        self.assertEqual(issues, [])

    def test_raise_from_e_flagged(self):
        code = """
try:
    do_something()
except Exception as e:
    raise CustomException("Failed") from e
"""
        issues = self._scan_code(code)
        self.assertEqual(len(issues), 1)
        self.assertIn("raise inside except without from None", issues[0])

    def test_raise_without_from_none_flagged(self):
        code = """
try:
    do_something()
except Exception as e:
    raise CustomException("Failed")
"""
        issues = self._scan_code(code)
        self.assertEqual(len(issues), 1)
        self.assertIn("raise inside except without from None", issues[0])

if __name__ == "__main__":
    unittest.main()
