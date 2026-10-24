#!/usr/bin/env python3
"""Scope lint: fail if tracked files reference out-of-scope projects, folders or identities.

This deployment is scoped to GCP project YOUR_PROJECT_ID and the GitHub repo
YOUR_ORG/YOUR_REPO. References to other projects, repos, local folders or
personal identities caused the cross-project issues found in the Oct 2026 review.

Usage: python scripts/scope_lint.py [--warn]
"""
import re
import subprocess
import sys

FORBIDDEN = [
    (r"codemender-prd", "foreign GCP project"),
    (r"codemender-poc", "foreign GCP project / repo"),
    (r"poc-flow", "foreign GitHub repo"),
    (r"161943671234", "foreign GCP project number"),
    (r"873180247571", "foreign GCP project number"),
    (r"[Aa]rgolis", "out-of-scope sibling project"),
    (r"admin@manishkgaur", "personal/global identity"),
    (r"GCP-Architecture-Guides", "foreign GitHub org"),
    (r"mgaur10/", "personal GitHub repos"),
    (r"elevate26", "global default project"),
    (r"agent-factory-ctrl", "global ADC quota project"),
    (r"/Desktop/Workspace/", "absolute local path"),
]

# Files allowed to mention the patterns (this linter defines them).
EXEMPT = {"scripts/scope_lint.py"}
BINARY_EXT = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".woff", ".woff2", ".ttf")


def main():
    warn_only = "--warn" in sys.argv
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True, check=True).stdout.split()
    hits = []
    for path in files:
        if path in EXEMPT or path.endswith(BINARY_EXT):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                for lineno, line in enumerate(fh, 1):
                    for pattern, why in FORBIDDEN:
                        if re.search(pattern, line):
                            hits.append(f"{path}:{lineno}: {why} ({pattern})")
        except (FileNotFoundError, IsADirectoryError):
            continue
    if hits:
        print(f"Scope lint: {len(hits)} out-of-scope reference(s):")
        print("\n".join(f"  {h}" for h in hits))
        return 0 if warn_only else 1
    print("OK: no out-of-scope references in tracked files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
