#!/usr/bin/env python3
"""Fail if a backend module imports a local module or name that does not exist.

Catches the class of bug behind review item A1 (main.py imported
`upload_codemender_state_bundle` from gcs_helpers, which never defined it), which
compileall cannot see. Only local modules (files/packages under the backend dir)
are checked; third-party imports are ignored.

Usage: python scripts/check_imports.py [backend_dir]
"""
import ast
import os
import sys


def local_modules(root):
    mods = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".venv", "node_modules")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root)[:-3].replace(os.sep, ".")
            if rel.endswith(".__init__"):
                rel = rel[: -len(".__init__")]
            mods[rel] = os.path.join(dirpath, fn)
    return mods


def defined_names(path):
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    names = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for tgt in targets:
                for sub in ast.walk(tgt):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, (ast.If, ast.Try)):
            # Names defined under top-level if/try (e.g. optional imports) count as defined.
            for sub in ast.walk(node):
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    names.add(sub.name)
                elif isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Store):
                    names.add(sub.id)
                elif isinstance(sub, (ast.Import, ast.ImportFrom)):
                    for alias in sub.names:
                        names.add((alias.asname or alias.name).split(".")[0])
    return names


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "backend")
    mods = local_modules(root)
    cache = {}
    problems = []
    for mod, path in sorted(mods.items()):
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                top = node.module.split(".")[0]
                if top not in {m.split(".")[0] for m in mods}:
                    continue  # third-party
                if node.module not in mods:
                    problems.append(f"{os.path.relpath(path, root)}:{node.lineno}: module '{node.module}' not found")
                    continue
                target = mods[node.module]
                names = cache.setdefault(target, defined_names(target))
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    sub_mod = f"{node.module}.{alias.name}"
                    if alias.name not in names and sub_mod not in mods:
                        problems.append(
                            f"{os.path.relpath(path, root)}:{node.lineno}: '{alias.name}' is not defined in '{node.module}'"
                        )
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top in {m.split(".")[0] for m in mods} and alias.name not in mods:
                        problems.append(f"{os.path.relpath(path, root)}:{node.lineno}: module '{alias.name}' not found")
    if problems:
        print("Unresolved local imports:")
        print("\n".join(f"  {p}" for p in problems))
        return 1
    print(f"OK: local imports resolve across {len(mods)} modules")
    return 0


if __name__ == "__main__":
    sys.exit(main())
