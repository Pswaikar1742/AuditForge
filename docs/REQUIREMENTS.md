# PS02 REQUIREMENT-TO-MODULE TRACEABILITY MATRIX

**Problem Statement:** PS02 — MCP Server Security Auditor  
**Track:** Open Weight AI & Open Source Tools (OpenForge Hackathon 2026)  

---

## Traceability Matrix

| ID | Mandatory PS02 Requirement | Implementing Module Path | Primary Class / Function | Verification Test Suite | Status |
|---|---|---|---|---|---|
| **REQ-01** | Connect to live MCP servers via standard transport protocols | `src/auditforge/catalog/client.py` | `MCPCatalogClient.discover_live` | `tests/integration/test_mcp_client.py` | `IN PROGRESS` |
| **REQ-02** | Canonical tool normalization & cryptographic fingerprinting | `src/auditforge/catalog/normalize.py` | `normalize_tool_definition`, `compute_tool_fingerprint` | `tests/unit/test_contracts.py` | `TESTED` |
| **REQ-03** | Baseline pinning & field-level catalog diffs (Rug Pull detection) | `src/auditforge/catalog/pinning.py` | `diff_catalogs` | `tests/unit/test_pinning.py` | `TESTED` |
| **REQ-04** | Static Python AST analysis for dangerous function calls & shell commands | `src/auditforge/analyzers/static.py` | `StaticAnalyzer.analyze` | `tests/unit/test_static.py` | `IN PROGRESS` |
| **REQ-05** | Automated Bandit AST vulnerability security scanner integration | `src/auditforge/analyzers/static.py` | `StaticAnalyzer._run_bandit` | `tests/unit/test_static.py` | `IN PROGRESS` |
| **REQ-06** | Deterministic Layer 0 regex & heuristic prompt injection checks | `src/auditforge/analyzers/description.py` | `DescriptionAnalyzer._layer0_scan` | `tests/unit/test_description.py` | `IN PROGRESS` |
| **REQ-07** | Open-Weight AI (Qwen3.5:9b / Llama3.2) semantic prompt injection detection | `src/auditforge/analyzers/description.py` | `DescriptionAnalyzer._layer1_llm_scan` | `tests/unit/test_description.py` | `IN PROGRESS` |
| **REQ-08** | Ephemeral, resource-constrained Docker container sandbox runner | `src/auditforge/sandbox/runner.py` | `DockerSandboxRunner.run_probe` | `tests/unit/test_sandbox.py` | `IN PROGRESS` |
| **REQ-09** | Safe schema-valid dynamic probe input generator | `src/auditforge/sandbox/probe_cases.py` | `generate_probe_cases` | `tests/unit/test_sandbox.py` | `IN PROGRESS` |
| **REQ-10** | Python audit hooks guest telemetry inside sandbox | `src/auditforge/sandbox/telemetry.py` | `AuditHookTelemetry` | `tests/unit/test_sandbox.py` | `IN PROGRESS` |
| **REQ-11** | Contract-to-Behavior Trust Gap reconciliation engine | `src/auditforge/analyzers/trust_gap.py` | `TrustGapAnalyzer.evaluate` | `tests/unit/test_trust_gap.py` | `IN PROGRESS` |
| **REQ-12** | Verifiable JSON Evidence Capsules generation & export | `src/auditforge/reports/json_report.py` | `export_json_report` | `tests/unit/test_reports.py` | `TESTED` |
| **REQ-13** | Human-readable Markdown executive & technical reports | `src/auditforge/reports/markdown.py` | `generate_markdown_report` | `tests/unit/test_reports.py` | `TESTED` |
| **REQ-14** | CLI interface with system doctor diagnostics and scan trigger | `src/auditforge/cli.py` | `doctor`, `pin`, `diff`, `scan` | `tests/unit/test_cli.py` | `TESTED` |
| **REQ-15** | FastAPI REST web service for scans and baselines | `src/auditforge/api/app.py` | `get_health`, `get_scan`, `get_baseline` | `tests/unit/test_api.py` | `TESTED` |
| **REQ-16** | React + Vite dashboard for real-time scan inspection | `dashboard/src/App.jsx` | `App` | `npm run build` | `TESTED` |
