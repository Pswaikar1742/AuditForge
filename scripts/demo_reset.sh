#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_DIR}"

echo "Resetting local database and evidence caches..."
rm -f auditforge.db audit_forge.db
rm -rf evidence_capsules/ scan_reports/

echo "AuditForge environment reset to clean state."
