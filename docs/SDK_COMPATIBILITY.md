# AUDITFORGE SDK & TOOLCHAIN COMPATIBILITY SPECIFICATION

## 1. Environment & SDK Verification Findings

During Gate 0 inspection and environment provisioning on Nobara Linux 44, the following toolchain compatibility profile was verified and locked:

### Python Runtime
- **System Default:** Python 3.14.7 (Experimental pre-release on Fedora/Nobara 44).
- **Target Runtime Selected:** **Python 3.12.13** (located at `/home/psw/.local/bin/python3.12`).
- **Rationale:** Python 3.12 is the highest stable Python release with 100% wheel support across all required cryptographic, C-extension (`cryptography`, `rpds_py`), and async libraries (`mcp`, `anyio`, `uvloop`).

### Official MCP Python SDK
- **Installed Version:** `mcp==2.3.0` (with `mcp-types==2.3.0`).
- **API Surface Verified:**
  - Client transport: `from mcp import StdioServerParameters, stdio_client, ClientSession`
  - Types: `from mcp.types import Tool, ToolAnnotations, CallToolRequest, CallToolResult`
  - Tool model attributes: `['name', 'title', 'description', 'input_schema', 'execution', 'output_schema', 'icons', 'annotations', 'meta']`
- **Important Note:** In `mcp>=2.0.0`, schema properties use snake_case (`input_schema`) by default with aliasing to camelCase (`inputSchema`). AuditForge's `normalize_tool_definition` accepts both forms seamlessly.

### Pydantic v2
- **Installed Version:** `pydantic==2.14.1`, `pydantic-core==2.50.1`.
- **Config Pattern:** Uses `ConfigDict(extra="ignore")` and `model_validate_json()`.

### Open-Weight AI (Ollama)
- **Ollama Version:** Client v0.34.2, Service running under systemd (`ollama.service`).
- **Available Models Verified:**
  1. `qwen3.5:9b` (Primary recommended: 9.7B parameters, Q4_K_M, 262k context, tools + thinking capabilities).
  2. `llama3.2:latest` (Fast fallback: 3.2B parameters, Q4_K_M, ultra-low VRAM footprint).
  3. `qwen2.5-coder:7b-instruct` (Code intelligence fallback).
- **HTTP Endpoint:** `http://localhost:11434/api/generate` with zero external internet requirement.

### Container Sandbox (Docker)
- **Docker Version:** 29.7.2, build 1.fc44.
- **Probe Image:** `auditforge-probe:latest` built from `docker/Dockerfile.probe`.
- **Base Image:** `python:3.12-slim` (replacing legacy `python:3.10-slim`).
- **Isolation Directives:** `network_mode="none"`, `mem_limit="256m"`, `cpu_quota=50000`, unprivileged user `sandboxuser`.
