# AUDITFORGE — ROUND 1 LIVE DEMONSTRATION SCRIPT

**Event:** OpenForge Hackathon 2026 | Problem Statement: PS02 (MCP Security Auditor)  
**Team:** InnoVision  
**Demonstrator:** Lead Systems Architect / Presenter  
**Target Window:** 1:00 PM IST (Frozen at 12:30 PM IST)  
**Primary Command:** `.venv/bin/python -m auditforge.cli demo`  
**Test Suite Command:** `.venv/bin/pytest -v`  
**Doctor Command:** `.venv/bin/python -m auditforge.cli doctor`  

---

## Part A: 4-Minute Comprehensive Demonstration Script

### Minute 0:00 – 0:45 | The Problem & The MCP Security Dilemma
- **Speaker:**
  > "Good afternoon judges. We are Team InnoVision presenting **AuditForge** for Problem Statement PS02 — an Evidence-First MCP Security Auditor.
  > 
  > The Model Context Protocol connects LLM agents directly to tools — granting access to internal databases, file systems, and bash shells. But today, agents trust MCP servers blindly based on unverified JSON schemas and docstrings.
  > 
  > If a tool lies about being read-only, hides a prompt injection in its description, or changes its input arguments after approval, the agent becomes an attacker's execution proxy.
  > 
  > AuditForge solves this with a **zero-trust, multi-layered auditing pipeline**: deterministic cryptographic pinning, static AST analysis, open-weight semantic inspection, containerized dynamic probing, and trust-gap reconciliation. Let's see it in action."

---

### Minute 0:45 – 1:30 | Stage 1 & Stage 2: Negative Control & Sandbox Traps
- **Action:** Run the master demonstration in your terminal:
  ```bash
  .venv/bin/python -m auditforge.cli demo
  ```
- **Pointing to Stage 1 on Screen:**
  > "Stage 1 tests our **Negative Control**. A good auditor doesn't flag harmless tools. Here, `clean_reader` declares two read-only tools. AuditForge connects over live stdio, verifies 0 vulnerabilities across all 5 verification gates, assigns a `VERIFIED` verdict, and pins an approved baseline SHA-256 fingerprint into our immutable database."

- **Pointing to Stage 2 on Screen:**
  > "Stage 2 audits `rogue_server`. Notice our static AST analyzer: it doesn't just treat `import subprocess` as a fatal alert; it accurately grades the import as `MEDIUM` confidence, while catching the actual dangerous `os.system(cmd)` shell invocation as `CRITICAL`.
  > Furthermore, dynamic probing runs in an isolated ephemeral Docker container with `network=none`, capped memory, non-root user, and internal audit hooks capturing telemetry."

---

### Minute 1:30 – 2:30 | Stage 3 & Stage 4: Open-Weight Intelligence & Trust Gap Reconciliation
- **Pointing to Stage 3 on Screen:**
  > "Stage 3 demonstrates **Open-Weight Semantic Intelligence**. Malicious servers sneak system overrides into tool descriptions.
  > 
  > AuditForge uses our local open-weight model (`qwen2.5-coder:7b` on Ollama) combined with deterministic heuristic gates. Notice the evidence: it flags delimiters like `<IMPORTANT>`, catches prompt overrides, and extracts the exact verbatim quote:
  > *'The tool description includes a system override instruction that bypasses safety guidelines...'*
  > We adhere strictly to PS02 rules: LLM output is capped at Advisory severity and always cites exact raw substring evidence."

- **Pointing to Stage 4 on Screen:**
  > "Stage 4 is our signature **Contract-to-Behavior Trust Gap Reconciliation**.
  > Look at `view_log`. Its MCP annotations claim `readOnly=True`. But our static inspection found an `os.remove()` call.
  > Instead of falsely claiming we witnessed a runtime deletion, AuditForge honestly reports:
  > `Contract discrepancy (SOURCE_INDICATOR / LIKELY)`.
  > We distinguish static potential from runtime execution, giving security engineers honest, trustworthy telemetry."

---

### Minute 2:30 – 3:30 | Stage 5: Baseline Pinning & Live Stdio Rug-Pull Detection
- **Pointing to Stage 5 on Screen:**
  > "Stage 5 tackles the most insidious attack in the MCP ecosystem: **The Post-Deployment Rug Pull**.
  > 
  > In production, an administrator approves version 1 of a tool. Later, the server mutates its code or parameters.
  > 
  > Here, AuditForge queries a live MCP server over stdio at `--version 1`, records its canonical SHA-256 hash, and then queries `--version 2` live over the official MCP protocol.
  > 
  > Notice the immediate field-level diff:
  > It catches that the tool `word_count` modified its description to smuggle in new logic, and introduced an unapproved parameter `lowercase`.
  > AuditForge flags this as an unauthorized schema mutation and alerts the operator immediately."

---

### Minute 3:30 – 4:00 | Verifiable Evidence Capsules & Summary
- **Speaker:**
  > "Every audit produces a tamper-evident JSON Evidence Capsule containing full AST lines, LLM quotes, container audit events, and canonical hashes.
  > 
  > In summary, AuditForge delivers:
  > 1. Authentic MCP SDK stdio protocol discovery.
  > 2. Ephemeral containerized probing with zero host execution.
  > 3. Honest, non-hallucinated trust-gap evidence.
  > 4. Deterministic baseline pinning to stop rug pulls.
  > 
  > All 22 tests pass in under 18 seconds. We are ready for your questions!"

---

## Part B: 60-Second Rapid-Fire Fallback Script

Use this version if the judging panel asks for an elevator pitch or a rapid 1-minute demo.

- **Action:** Execute the demo command:
  ```bash
  .venv/bin/python -m auditforge.cli demo
  ```
- **Speaker (rapid, confident delivery):**
  > "AuditForge is an evidence-first security auditor for Model Context Protocol servers. In 60 seconds, our live demo executes all 5 security gates:
  > 
  > 1. **Negative Control:** Connects live via stdio to a clean server, confirms 0 findings, and computes a canonical SHA-256 baseline.
  > 2. **Static & Sandbox Inspection:** Detects `os.system` execution via AST and contains it within an isolated non-root Docker guest with network disabled.
  > 3. **Prompt Injection Intelligence:** Local Qwen2.5-Coder detects hidden override instructions with verbatim quote citations.
  > 4. **Trust-Gap Reconciliation:** Catches a tool claiming `readOnly=True` while harboring file deletion logic, truthfully graded as `SOURCE_INDICATOR`.
  > 5. **Live Protocol Rug-Pull Diff:** Detects real-time parameter and description mutations on a running server without relying on static mock files.
  > 
  > Every finding is backed by cryptographic hashes and verifiable JSON evidence capsules. 22 automated tests passing. Zero host execution. Thank you!"

---

## Part C: Anticipated Judge Questions & Bulletproof Answers

#### Q1: "Are you actually running the target tool, or just inspecting its Python code?"
- **Answer:**  
  "We do both, and we strictly keep them distinct. Static AST inspection scans the source code to find hidden functions or libraries (`SOURCE_INDICATOR / LIKELY`). Then, our dynamic sandbox runner executes schema-valid inputs over the official MCP `tools/call` protocol inside an ephemeral Docker container (`network=none`, 256MB memory cap). Telemetry audit hooks (`sys.addaudithook`) capture OS calls at runtime. If a tool doesn't execute a side-effect during runtime, we never claim an observed attempt."

#### Q2: "Why use an open-weight LLM like Qwen2.5-Coder instead of regex or commercial APIs?"
- **Answer:**  
  "Regex and delimiter checks can catch known tags like `<IMPORTANT>`, but attackers use semantic obfuscation, roleplay, and indirect phrasing. Open-weight models running locally via Ollama provide semantic understanding while guaranteeing complete data privacy and zero API dependency. Furthermore, we cap LLM findings at Advisory and require verbatim substring quotes in the evidence capsule to prevent hallucinated vulnerabilities."

#### Q3: "How do you detect when an MCP server changes after an admin has already approved it?"
- **Answer:**  
  "We normalize all tool definitions—stripping non-semantic whitespace and sorting schema keys deterministically—and compute a canonical SHA-256 hash stored in an immutable SQLite baseline. When an audit re-runs, we query the server live and perform a field-level diff. If properties, descriptions, or types changed, AuditForge immediately raises a Rug-Pull alert with exact before-and-after values."

#### Q4: "What happens if a malicious tool tries to break out of the sandbox?"
- **Answer:**  
  "The tool never runs on the host OS. Dynamic probing runs inside an ephemeral Docker container with `--network=none`, `--memory=256m`, `--cpus=0.5`, `--security-opt no-new-privileges:true`, `--cap-drop ALL`, and runs under a non-root `audituser` (UID 10001). Host isolation is strictly enforced at the container namespace and cgroup level."
