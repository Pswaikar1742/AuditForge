# CODEX2 Security Prober Report

## Result

Implemented real Python AST/Bandit static analysis and a Docker-backed probe runner on `feat/security-prober`.

## Files inspected

- `AGENTS.md`, `CODEX2_TASK.md`, `docs/CONTRACTS.md`
- `src/auditforge/core/contracts.py`
- `src/auditforge/analyzers/static.py`
- `src/auditforge/sandbox/{runner.py,probe_cases.py,telemetry.py}`
- `docker/Dockerfile.probe`
- `fixtures/clean_reader/server.py`
- `fixtures/rogue_server/server.py`
- `fixtures/lying_annotations/server.py`
- Existing unit tests and `pyproject.toml`

## Files changed

- `src/auditforge/analyzers/static.py`: AST parsing without target imports; shell, subprocess, pickle, network, write, deletion detection; Bandit JSON integration; source-linked evidence and findings.
- `src/auditforge/sandbox/runner.py`: bounded Docker execution, JSON guest protocol, status mapping, timeout handling, safe read-only target mount, non-root and resource controls.
- `src/auditforge/sandbox/probe_cases.py`: bounded schema-derived inputs.
- `src/auditforge/sandbox/telemetry.py`: guest audit-hook capture for `open`, `socket.connect`, and `subprocess.Popen`.
- `docker/Dockerfile.probe`: adds `/app/src` to `PYTHONPATH` so the guest entrypoint is importable.

The frozen `src/auditforge/core/contracts.py` was not modified.

## Verification commands and actual output

`PYTHONPATH=src .venv/bin/python -m pytest`

```text
............                                                             [100%]
12 passed in 1.12s
```

`PYTHONPATH=src .venv/bin/python` static fixture check:

```text
fixtures/clean_reader/server.py findings= 0 evidence= 0
fixtures/rogue_server/server.py findings= 7 evidence= 7
  AST-SUBPROCESS-001 CRITICAL None
  AST-SHELL-001 CRITICAL system_diagnostic
  AST-SUBPROCESS-002 CRITICAL system_diagnostic
  BANDIT-B404 LOW None
  BANDIT-B605 HIGH None
  BANDIT-B607 LOW None
  BANDIT-B603 LOW None
fixtures/lying_annotations/server.py findings= 1 evidence= 1
  AST-FILE-002 HIGH view_log
```

`docker build -t auditforge-probe:latest -f docker/Dockerfile.probe .`

```text
#10 DONE 4.6s
```

Container probe checks against `fixtures/clean_reader/server.py`:

```text
OK: status=OK, tool=search_docs, telemetry_events=2
TOOL_ERROR: status=TOOL_ERROR, error=AttributeError: module 'auditforge_guest_target' has no attribute 'missing_tool'
TIMEOUT: status=TIMEOUT, error=Probe exceeded 0.00s
SKIPPED: status=SKIPPED, error=Target source file does not exist: /home/psw/nope/server.py
```

The generated Docker command uses `--network none`, `--memory 256m`, `--cpus 0.5`, `--pids-limit 64`, `--read-only`, a `16m` no-exec `/tmp`, `--user 1000:1000`, and a read-only target mount.

## Commit and delivery

- Implementation commit: `0afa261bbd9db842a20e9687529a15aaeec0b1f6`
- Branch: `feat/security-prober`
- Destination: `origin/feat/security-prober`

## Limitations and integration notes

- The repository fixtures are plain Python handler modules rather than full MCP stdio servers. The guest protocol therefore invokes the fixture handler by its catalog tool name; integrating a real MCP stdio transport remains an integration-workstream task.
- Bandit is run as an analysis subprocess over source and the target module is never imported on the host.
- Audit hooks are guest telemetry only; Docker namespaces provide isolation.
- Probe outcomes do not claim that a blocked operation exfiltrated data.
