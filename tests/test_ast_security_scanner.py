import unittest
import ast
import tempfile
import os
from ast_security_scanner import scan_file, SecurityVisitor

class TestASTSecurityScanner(unittest.TestCase):
    def check_code(self, code: str):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            filepath = f.name

        try:
            return scan_file(filepath)
        finally:
            os.remove(filepath)

    def test_bare_raise_inside_except(self):
        code = '''
try:
    pass
except Exception:
    raise
'''
        issues = self.check_code(code)
        self.assertEqual(len(issues), 0, "Bare raise inside except should pass without warnings.")

    def test_explicit_traceback_suppression_from_none(self):
        code = '''
try:
    pass
except Exception:
    raise RuntimeError() from None
'''
        issues = self.check_code(code)
        self.assertEqual(len(issues), 0, "Explicit traceback suppression 'from None' should pass without warnings.")

    def test_explicit_chaining_from_e(self):
        code = '''
try:
    pass
except Exception as e:
    raise RuntimeError() from e
'''
        issues = self.check_code(code)
        self.assertEqual(len(issues), 1, "Explicit chaining 'from e' inside except must be flagged.")
        self.assertIn("raise inside except without from None", issues[0])

    def test_unsuppressed_raise_inside_except(self):
        code = '''
try:
    pass
except Exception:
    raise RuntimeError()
'''
        issues = self.check_code(code)
        self.assertEqual(len(issues), 1, "Unsuppressed 'raise Exception()' inside except must be flagged.")
        self.assertIn("raise inside except without from None", issues[0])

if __name__ == '__main__':
    unittest.main()
