#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

PYTHON_BIN=".venv/bin/python"
if [ ! -f "${PYTHON_BIN}" ]; then
    PYTHON_BIN="python3"
fi

echo "=== [1/4] Running Environment Diagnostics ==="
"${PYTHON_BIN}" -m auditforge.cli doctor

echo "=== [2/4] Testing CLI Help Command ==="
"${PYTHON_BIN}" -m auditforge.cli --help > /dev/null
echo "CLI Help: OK"

echo "=== [3/4] Running Test Suite ==="
"${PYTHON_BIN}" -m pytest -q

echo "=== [4/4] Checking Git Status ==="
git status --short

echo "=== ALL AUDITFORGE VERIFICATION GATES PASSED ==="
