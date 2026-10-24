#!/usr/bin/env bash
# Pre-commit / pre-deploy gate for the CodeMender backend.
#   1. compileall          - syntax errors
#   2. check_imports.py    - imports of local modules/names that don't exist
#   3. scope_lint.py       - references to out-of-scope projects, repos, folders, identities
#   4. pytest              - unit tests in backend/tests
# Writes no bytecode into the tree (PYTHONPYCACHEPREFIX points at a temp dir).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-$ROOT/.venv/bin/python}"
if [[ ! -x "$PY" ]]; then
  echo "Missing virtualenv. Create it with:"
  echo "  python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt -c backend/constraints.txt pytest"
  exit 2
fi

CACHE_DIR="$(mktemp -d)"
trap 'rm -rf "$CACHE_DIR"' EXIT
export PYTHONPYCACHEPREFIX="$CACHE_DIR/pycache"
export PYTHONDONTWRITEBYTECODE=1

echo "== 1/4 compileall + shell syntax"
"$PY" -m compileall -q backend scripts
for script in scripts/*.sh deploy.sh; do
    bash -n "$script"
done

echo "== 2/4 local imports"
"$PY" scripts/check_imports.py backend

echo "== 3/4 scope lint"
"$PY" scripts/scope_lint.py ${SCOPE_LINT_ARGS:-}

echo "== 4/4 unit tests"
(cd backend && "$PY" -m pytest -q -p no:cacheprovider tests)

echo "All checks passed."
