#!/usr/bin/env bash
# ==============================================================================
# AUDITFORGE — ALL-IN-ONE END-TO-END DEMO SCRIPT
# Problem Statement: PS02 — MCP Server Security Auditor
#
# Runs:
# 1. Environment & Pre-flight Diagnostics
# 2. Fast Test Suite Verification (Unit + Integration Gates)
# 3. Multi-Scenario CLI Security Scans (Positive, Negative, Trust Gap, Pinning)
# 4. Verifiable Report Generation (Markdown + JSON Evidence Capsules)
# 5. FastAPI Backend & Side-by-Side Comparison Verification
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_DIR}"

COLOR_RESET="\033[0m"
COLOR_BOLD="\033[1m"
COLOR_CYAN="\033[36m"
COLOR_GREEN="\033[32m"
COLOR_YELLOW="\033[33m"
COLOR_RED="\033[31m"

header() {
    echo -e "\n${COLOR_BOLD}${COLOR_CYAN}══════════════════════════════════════════════════════════════${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}  $1${COLOR_RESET}"
    echo -e "${COLOR_BOLD}${COLOR_CYAN}══════════════════════════════════════════════════════════════${COLOR_RESET}\n"
}

success() {
    echo -e "${COLOR_GREEN}✔ $1${COLOR_RESET}"
}

warn() {
    echo -e "${COLOR_YELLOW}⚠ $1${COLOR_RESET}"
}

# 1. Resolve Python executable
PYTHON_BIN=".venv/bin/python"
if [ ! -f "${PYTHON_BIN}" ]; then
    PYTHON_BIN="python3"
fi

header "STAGE 1: Environment & System Pre-flight Checks"
echo "Repository: ${REPO_DIR}"
echo "Python binary: ${PYTHON_BIN}"
"${PYTHON_BIN}" -m auditforge.cli doctor

# Check Docker daemon availability
if docker info > /dev/null 2>&1; then
    success "Docker daemon: Active (sandbox container isolation available)"
else
    warn "Docker daemon: Inactive or unprivileged (scans will use safe static+stdio mode)"
fi

# Check Ollama daemon availability
if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
    success "Ollama daemon: Active on port 11434 (Qwen3.5 LLM analysis available)"
else
    warn "Ollama daemon: Offline (scans will use deterministic Layer 0 regex heuristics)"
fi

header "STAGE 2: Fast Test Suite Verification (Regression Gates)"
echo "Executing test suite..."
"${PYTHON_BIN}" -m pytest tests/unit/ -o cache_dir=/tmp/pytest_cache -q
success "All unit tests passed cleanly."

header "STAGE 3: CLI Security Audit Demonstrations"
rm -f auditforge.db audit_forge.db

echo -e "\n${COLOR_BOLD}A. Positive Control: Rogue Server (Subprocess & Shell Execution)${COLOR_RESET}"
"${PYTHON_BIN}" -m auditforge.cli scan fixtures/rogue_server --no-docker --no-llm || true

echo -e "\n${COLOR_BOLD}B. Negative Control: Clean Reader Server (Zero Findings Control)${COLOR_RESET}"
"${PYTHON_BIN}" -m auditforge.cli scan fixtures/clean_reader --no-docker --no-llm

echo -e "\n${COLOR_BOLD}C. Trust Gap Detection: Lying Annotations (readOnly=True vs File Deletion)${COLOR_RESET}"
"${PYTHON_BIN}" -m auditforge.cli scan fixtures/lying_annotations --no-docker --no-llm || true

echo -e "\n${COLOR_BOLD}D. Supply Chain Baseline Pinning & Live Stdio Diff${COLOR_RESET}"
"${PYTHON_BIN}" -m auditforge.cli pin fixtures/clean_reader --id clean_reader
echo "Verifying identical baseline match..."
"${PYTHON_BIN}" -m auditforge.cli diff fixtures/clean_reader --id clean_reader
echo "Detecting post-approval catalog mutation / drift..."
"${PYTHON_BIN}" -m auditforge.cli diff fixtures/rug_pull --id clean_reader || true

header "STAGE 4: Verifiable Report Generation (Evidence Capsules)"
echo "AuditForge automatically generates cryptographic JSON evidence capsules and Markdown reports in scan_reports/:"
ls -lh scan_reports/

header "STAGE 5: FastAPI Backend & Side-by-Side Comparison Gate"
BACKEND_PORT=8000
echo "Launching FastAPI server on port ${BACKEND_PORT} in background..."
"${PYTHON_BIN}" -m uvicorn auditforge.api.app:app --host 127.0.0.1 --port ${BACKEND_PORT} > /tmp/auditforge_demo_api.log 2>&1 &
API_PID=$!
trap "kill -9 ${API_PID} > /dev/null 2>&1 || true" EXIT

echo "Waiting for API to start up..."
sleep 2

# Verify Health
HEALTH_RES=$(curl -s http://127.0.0.1:${BACKEND_PORT}/health || echo "")
if [[ "${HEALTH_RES}" == *"OK"* ]] || [[ "${HEALTH_RES}" == *"ok"* ]]; then
    success "Backend health check: OK (${HEALTH_RES})"
else
    warn "Backend health check response: ${HEALTH_RES}"
fi

# Verify Comparison Pairs Listing
echo "Querying available comparison pairs..."
PAIRS_COUNT=$("${PYTHON_BIN}" -c 'import urllib.request, json; data = json.loads(urllib.request.urlopen("http://127.0.0.1:'${BACKEND_PORT}'/api/pairs").read()); print(len(data))')
success "Comparison pairs available: ${PAIRS_COUNT} pairs registered."

# Trigger Side-by-Side Verification via POST
echo "Triggering side-by-side verification: Command Injection vs Safe In-Memory Diagnostic..."
REMEDIATED_ROGUE=$("${PYTHON_BIN}" -c '
import urllib.request, json
req = urllib.request.Request("http://127.0.0.1:'${BACKEND_PORT}'/api/compare/pair_rogue_server", data=b"{}", headers={"Content-Type": "application/json"})
res = json.loads(urllib.request.urlopen(req).read())
delta = res.get("comparison_delta", {})
cnt = delta.get("eliminated_findings_count")
rules = delta.get("eliminated_rule_ids")
rem = delta.get("is_fully_remediated")
print(f"Eliminated {cnt} finding(s) {rules} | Remediated: {rem}")
')
success "Pair comparison complete -> ${REMEDIATED_ROGUE}"

# Trigger Live Rug-Pull Comparison via POST
echo "Triggering authentic live stdio Rug-Pull verification..."
REMEDIATED_RUGPULL=$("${PYTHON_BIN}" -c '
import urllib.request, json
req = urllib.request.Request("http://127.0.0.1:'${BACKEND_PORT}'/api/compare/pair_rug_pull", data=b"{}", headers={"Content-Type": "application/json"})
res = json.loads(urllib.request.urlopen(req).read())
delta = res.get("comparison_delta", {})
cnt = delta.get("eliminated_findings_count")
rules = delta.get("eliminated_rule_ids")
rem = delta.get("is_fully_remediated")
print(f"Eliminated {cnt} finding(s) {rules} | Remediated: {rem}")
')
success "Rug-Pull live comparison complete -> ${REMEDIATED_RUGPULL}"

header "STAGE 6: Complete Verification Summary"
echo -e "${COLOR_GREEN}${COLOR_BOLD}ALL AUDITFORGE DEMONSTRATIONS AND GATES COMPLETED SUCCESSFULLY!${COLOR_RESET}"
echo "Evidence-first guarantees:"
echo " • Zero fake findings: all results derived from AST, stdio discovery, or container telemetry."
echo " • Supply-chain cryptographic pinning: detects unauthorized tool mutations."
echo " • Trust gap reconciliation: flags discrepancies between metadata and implementation."
echo " • Evidence manifest digest: SHA-256 verifiable content-addressable audit capsules."
echo ""
echo "To explore the interactive React dashboard:"
echo "  1. Start backend:   .venv/bin/uvicorn auditforge.api.app:app --port 8000"
echo "  2. Start frontend:  cd dashboard && npm run dev"
echo "  3. Open browser:    http://localhost:5173"
echo ""
