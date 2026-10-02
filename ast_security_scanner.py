import ast
import os

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []
        self.in_except = False
        self.current_except_names = []

    def visit_ExceptHandler(self, node):
        old_in_except = self.in_except
        self.in_except = True
        if node.name:
            self.current_except_names.append(node.name)

        self.generic_visit(node)

        if node.name:
            self.current_except_names.pop()
        self.in_except = old_in_except

    def visit_Call(self, node):
        # Check for logger.* calls
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name) and node.func.value.id in ("logging", "logger"):
            if node.func.attr == "exception":
                self.issues.append(f"Line {node.lineno}: {node.func.value.id}.exception automatically passes exc_info=True")
            # Check for exc_info=True
            for kw in node.keywords:
                if kw.arg == "exc_info":
                    if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.issues.append(f"Line {node.lineno}: {node.func.value.id}.{node.func.attr} passes exc_info=True")
                    elif isinstance(kw.value, ast.Name) and kw.value.id == "True":
                        self.issues.append(f"Line {node.lineno}: {node.func.value.id}.{node.func.attr} passes exc_info=True")
            # Check for raw exception variables in args
            for arg in node.args:
                if isinstance(arg, ast.Name) and (arg.id == "e" or arg.id in self.current_except_names):
                    self.issues.append(f"Line {node.lineno}: {node.func.value.id}.{node.func.attr} passes raw exception variable '{arg.id}'")

        self.generic_visit(node)

    def visit_Raise(self, node):
        if self.in_except:
            if getattr(node, 'cause', None) is None:
                self.issues.append(f"Line {node.lineno}: raise inside except without from None")
        self.generic_visit(node)

def scan_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        tree = ast.parse(f.read(), filename=filepath)
    visitor = SecurityVisitor()
    visitor.visit(tree)
    return visitor.issues

def scan_directory(dirpath):
    all_issues = {}
    for root, _, files in os.walk(dirpath):
        for file in files:
            if file.endswith('.py'):
                path = os.path.join(root, file)
                issues = scan_file(path)
                if issues:
                    all_issues[path] = issues
    return all_issues

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    issues = scan_directory(target)
    if issues:
        for path, issue_list in issues.items():
            for issue in issue_list:
                print(f"{path}: {issue}")
        sys.exit(1)
    else:
        print("No AST security issues found.")
