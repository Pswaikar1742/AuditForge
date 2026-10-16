# AUDITFORGE SECURITY MODEL, THREAT LANDSCAPE & LIMITATIONS

## 1. Security Architecture & Threat Model

AuditForge audits untrusted MCP servers. Because target servers may contain adversarial code, prompt injection payloads, or covert exfiltration channels, AuditForge enforces a defense-in-depth posture:

1. **Host Isolation:** Target tools must never execute directly on the developer's host machine. Execution is delegated to Docker containers.
2. **Deterministic Pre-Filtering:** Syntactic AST and regex screening execute prior to any model inference to prevent LLM poisoning from altering scanner logic.
3. **Local-Only Open-Weight Inference:** All semantic evaluations run via local Ollama models; no proprietary API keys or external services are contacted.

---

## 2. Honest Security Boundaries & Known Limitations

To maintain academic and professional integrity, AuditForge explicitly documents the technical boundaries of each security mechanism:

### 1. Static AST Analysis Limitations
- **Dynamic Obfuscation:** Python AST analysis inspects syntactic structures. Highly dynamic constructs (`getattr(__builtins__, "eval")`, `base64.b64decode(...)`, obfuscated bytecode) cannot be statically resolved without symbolic execution or dynamic tracing.
- **Scope:** AST analysis only analyzes Python source code. Compiled extensions (`.so`, C extensions) or polyglot wrappers require runtime container sandboxing.

### 2. Open-Weight Model Classification Limitations
- **Non-Determinism:** LLM classification produces probabilistic outputs. While temperatures are set to `0.0`, minor prompt formatting variations may cause edge-case classifications to shift.
- **Adversarial Jailbreaks:** Sophisticated prompt injection payloads designed to evade Qwen/Llama tokenizers may escape detection. For this reason, Layer 0 deterministic heuristic rules always run alongside LLM evaluations.

### 3. Docker Sandbox Isolation Boundaries
- **Container Escapes:** While Docker provides namespace and cgroup isolation with unprivileged user execution, kernel-level vulnerabilities (e.g. Linux 0-days) could theoretically escape container confinement.
- **Network Mode:** By default, containers run with `network_mode="none"`. If a user explicitly enables network for testing, container egress must be routed through monitored virtual interfaces.

### 4. Python Audit Hooks (`sys.addaudithook`)
- **Telemetry, NOT Isolation:** Python audit hooks run in user space within the Python interpreter process. An attacker with arbitrary memory write or C extension execution can disable or bypass audit hooks. Therefore, AuditForge strictly treats audit hooks as **guest-side telemetry**, never as host security barriers.

### 5. Definition-Only Cryptographic Fingerprints
- **Specification vs Implementation:** Tool SHA-256 fingerprints hash the canonical MCP declaration (name, description, schema, annotations). A server could modify its underlying Python source code without modifying its MCP tool declaration. To address this, AuditForge combines catalog fingerprinting with static AST hash checks.

### 6. Synthetic Test Fixtures
- The 5 controlled test fixtures (`clean_reader`, `rogue_server`, `poisoned_description`, `rug_pull`, `lying_annotations`) represent synthetic unit baselines. Real-world MCP tools require broader fuzzing and multi-step orchestration analysis.
