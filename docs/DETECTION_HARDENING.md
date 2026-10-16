# Description detection hardening v1

Base: develop `52bcef7631f515ebc939f5e9c6b3d14433718985`. Work occurs only in
`/home/psw/auditforge-detection-hardening`, branch `feat/detection-hardening-v1`.
Forger and the existing analysis worktree were inspected twice before detector writes:
neither had edits to DescriptionAnalyzer; Forger had an unrelated trust_gap.py edit.
The user instructed continuation after the ownership clarification. No shared worktree,
API, frontend, orchestrator, frozen contract or AttackLab PR #2 is modified.

## Behavior and evidence

The public `(findings, evidence)` interface and optional model settings are preserved.
Normalization uses NFKC on bounded combining/Hangul-Jamo clusters, selected zero-width
characters (U+200B, U+2060, U+FEFF), whitespace collapse, and token-boundary Markdown
asterisks/underscores. Language-significant U+200C/U+200D remain unchanged. This is not
universal confusable, Markdown, or multilingual interpretation. Original ToolRecord
strings are never mutated. ASCII text without presentation characters uses an identity map.

Each rule match records the original string field, Python-code-point span, exact original
quote, SHA-256 of that field, normalized match/span, and the normalized-character-to-original
interval map for that match. NFKC expansions can map several characters to one original
span. Removed characters within a match remain in the raw quote. Normalized text is never
substituted as a verbatim evidence quote. Schema keys and raw string values are inspected
separately; matches cannot be created by concatenating unrelated fields.

Triage is in EvidenceRecord.raw_data, not new frozen enums:

- SUSPICIOUS: a deterministic instruction candidate produces a linked Finding.
- CONTEXTUAL_BENIGN: explicit explanatory/rejection context, or no deterministic indicator;
  evidence remains available and never claims complete security.
- REVIEW_REQUIRED: ambiguous instruction adoption, sensitive-file references without enough
  intent, or inspection limits. No fabricated finding is emitted merely to represent uncertainty.

Quoted/JSON text is still inspected. Educational quotation handling uses bounded local
context; adoption language prevents automatic benign classification. Every candidate is
scanned up to the match budget, so an educational preface cannot automatically suppress a
later direct instruction. These remain heuristics, not an adversarial context-understanding guarantee.

The existing orchestrator recognizes `skipped or timed out` in evidence summaries. Unresolved
deterministic review and inspection limits retain that marker, causing ERROR coverage instead
of an empty-finding PASS. This compatibility bridge is intentionally retained without changing
orchestrator.py; a future owner should consume structured status rather than matching prose.
The scanner can retain positive evidence alongside partial-coverage warnings.

## Bounded execution

Aggregate source text: 131072 characters; schema fields: 512; traversal nodes: 4096; depth: 16;
normalization cluster: 32 code points; normalized output: 131072 characters; match capsules: 32.
Resource limits yield explicit partial/unassessed evidence, never silent truncation. Regex gaps
are bounded (96/160/256 characters). Near-matching negative inputs have a CPU/address-space
regression test. Bounds limit work as a function of input size; they do not promise constant latency.

Optional semantic analysis makes at most one call per tool. Clear deterministic positives and
fully contextual match sets do not need that call. The system instruction is separate from JSON
untrusted data; the request gives the model no tools or authority over scanner configuration.
No model output can downgrade deterministic findings or clear retained uncertainty. This does
not claim models cannot be prompt-injected: results remain advisory and exact raw quotes are required.

Semantic limits: description 8192 characters, full system+data prompt 4096 UTF-8 bytes, response
65536 bytes, 512 generated tokens, context request 8192 tokens. Invalid response schemas, invented
quotes, nonfinite confidence, token exhaustion, unavailable service and timeouts are unassessed.
Socket timeouts are capped at 30 seconds; a monotonic deadline is checked between bounded reads.
An in-progress socket read can extend beyond the deadline by up to the socket timeout; this is not
hard process cancellation, and OS DNS resolution is not supervised by a subprocess watchdog.
No live model quality improvement or prompt-injection immunity is claimed. KOALA source/contracts
are unchanged; semantic tests using synthetic model replies test parser behavior, not model accuracy.

## Evaluation protocol

`benchmarks/detection_hardening/evaluation_v1.json` was frozen at `df6f00c` before detector edits
and before its first execution. It has 24 new cases/rationales in workflow redirection, answer
contamination, encoded reconstruction, multilingual intent, scope/secrets and mixed-document
families. This reduces template reuse relative to published Phase 2 obfuscation examples but
cannot eliminate conceptual leakage. It is author-labelled, not independently human-reviewed or
blinded; do not present it as external independent validation. Do not tune rules on its results.
The published 18-case heldout-v1 is explicitly development/regression data in this sprint.

The evaluation harness imports the unchanged AttackLab engine from its separate checkout at
`32f0f0b`. Baseline source is exported from develop and checked against a fixed SHA-256 before
loading. Both variants use the same Python process configuration, seed, inputs, no cache, no
LLM, and the same coverage adapter. Full corpus digests verify equivalent inputs. The adapter
maps explicit detector abstentions into AttackLab's unassessed/error channel; reports separate
abstentions from malformed records/errors and retain per-family denominators. Positive and
negative abstentions and detection fraction over all labelled positives are reported so selective
coverage cannot hide misses. Legacy AttackLab v2 alone does not interpret these new triage records;
use this adapter for correct coverage metrics until the AttackLab owner integrates that capability.

Small evaluation sets export original inputs, actual findings and evidence to decisions.jsonl.
Throughput sets retain bounded aggregates only. Report detector hashes include the normalization
helper separately. Temporary SQLite cardinality storage remains bounded in RAM but grows on disk.
Confidence intervals are not justified for these dependent designed sets. Single workstation runs
are descriptive measurements, not production readiness or statistically established speed claims.

Commands (from the isolated checkout; outputs outside Git):

```bash
PYTHONPATH=src python -m pytest tests/unit/test_description_hardening.py
PYTHONPATH=src:/home/psw/auditforge-attacklab python -m pytest /home/psw/auditforge-attacklab/tests/unit/test_attacklab.py
git show 52bcef7:src/auditforge/analyzers/description.py > /home/psw/detection-hardening-evidence/baseline_description.py
PYTHONPATH=src:/home/psw/auditforge-attacklab python benchmarks/detection_hardening/evaluate.py --detector baseline --baseline-source /home/psw/detection-hardening-evidence/baseline_description.py --workload independent --output /home/psw/detection-hardening-evidence/baseline-independent
PYTHONPATH=src:/home/psw/auditforge-attacklab python benchmarks/detection_hardening/evaluate.py --detector hardened --workload independent --output /home/psw/detection-hardening-evidence/hardened-independent
```

Integration tests that start target fixtures run in a non-root networkless Docker container
(256 MiB memory, 0.5 CPU, read-only root, no capabilities, no-new-privileges). The two Docker-aware
live MCP tests run via the dedicated host venv and launch only constrained Docker targets.
No target MCP server is run on the Nobara host. Live KOALA installation testing is explicitly
skipped in the test container, where KOALA is absent; mocked compatibility tests still execute.

## Executed acceptance evidence

Measured clean implementation: `7c0faba8affceeca332c9d3813934bf34457e1b1`. All 12 comparisons have identical paired corpus hashes and detector-call counts, with caching and inference disabled. No detector changes were made after evaluation.

Actual terminal summaries:

```text
New hardening unit tests: 39 passed, 724 warnings in 0.60s
Final constrained-container suite: 123 passed, 1 skipped in 141.69s (0:02:21)
Docker-backed live MCP tests: 2 passed in 16.60s
Unchanged AttackLab compatibility tests: 19 passed, 596 warnings in 1.98s
```

Python 3.14 warnings are pytest-asyncio deprecations. The container uses Python 3.12; its single skip is the live KOALA installation test, not a claimed pass. The separate isolated live KOALA result is reported below. Actual unavailable-model probing against 127.0.0.1:1 returned `Connection refused`, `triage=REVIEW_REQUIRED`, `status=SKIPPED`, with no finding. Timeout and malformed-response tests use explicitly mocked responses and are not live model-quality evidence.

Quality (rates are conditional on assessed cases; abstentions remain in submitted counts):

| Dataset | Detector | Assessed/submitted | TP | TN | FP | FN | Abstentions | Precision | Recall | F1 | FPR | FNR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| independent 24 | baseline | 24/24 | 3 | 10 | 2 | 9 | 0 | 0.60000 | 0.25000 | 0.35294 | 0.16667 | 0.75000 |
| independent 24 | hardened | 23/24 | 3 | 11 | 0 | 9 | 1 | 1.00000 | 0.25000 | 0.40000 | 0.00000 | 0.75000 |
| heldout 18 | baseline | 18/18 | 5 | 4 | 3 | 6 | 0 | 0.62500 | 0.45455 | 0.52632 | 0.42857 | 0.54545 |
| heldout 18 | hardened | 18/18 | 11 | 7 | 0 | 0 | 0 | 1.00000 | 1.00000 | 1.00000 | 0.00000 | 0.00000 |
| repeated 10000 | baseline | 9132/10000 | 2609 | 5218 | 435 | 870 | 0 | 0.85710 | 0.74993 | 0.79994 | 0.07695 | 0.25007 |
| repeated 10000 | hardened | 9132/10000 | 3479 | 5653 | 0 | 0 | 0 | 1.00000 | 1.00000 | 1.00000 | 0.00000 | 0.00000 |
| diverse 10000 | baseline | 9000/10000 | 3000 | 1000 | 1000 | 4000 | 0 | 0.75000 | 0.42857 | 0.54545 | 0.50000 | 0.57143 |
| diverse 10000 | hardened | 8000/10000 | 7000 | 1000 | 0 | 0 | 1000 | 1.00000 | 1.00000 | 1.00000 | 0.00000 | 0.00000 |
| maximum 10000 | baseline | 10000/10000 | 3333 | 1112 | 1111 | 4444 | 0 | 0.75000 | 0.42857 | 0.54545 | 0.49978 | 0.57143 |
| maximum 10000 | hardened | 8889/10000 | 7777 | 1112 | 0 | 0 | 1111 | 1.00000 | 1.00000 | 1.00000 | 0.00000 | 0.00000 |
| diverse 100000 | baseline | 90000/100000 | 30000 | 10000 | 10000 | 40000 | 0 | 0.75000 | 0.42857 | 0.54545 | 0.50000 | 0.57143 |
| diverse 100000 | hardened | 80000/100000 | 70000 | 10000 | 0 | 0 | 10000 | 1.00000 | 1.00000 | 1.00000 | 0.00000 | 0.00000 |

The new family challenge keeps recall at 25% (3/12 malicious cases). One baseline benign-document FP is corrected to negative; one sensitive-file FP is converted to explicit review. Hardened coverage is 23/24, with one negative abstention and zero positive abstentions. No broader recall improvement is established. Published heldout-v1 gains are development/regression results only.

Diverse data contains deliberately oversized records (10% skipped before either detector). Hardened additionally abstains on the educational quotations because negated adoption wording (`do not obey it`) still triggers the conservative adoption heuristic. This is a known false-abstention regression. Reported perfect assessed accuracy does **not** imply full coverage or independent generalization. Repeated data retains its intentionally malformed records as errors.

Performance (processing latency includes validation, normalization, evidence and adapter work; detector-only metrics are also in JSON):

| Dataset | Detector | Runtime s | Submitted/s | Peak RSS MiB | Mean ms | p50 ms | p95 ms | p99 ms | Detector calls |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| independent 24 | baseline | 0.0057 | 4233.3 | 37.76 | 0.1956 | 0.1061 | 0.9103 | 1.0055 | 24 |
| independent 24 | hardened | 0.0076 | 3157.1 | 38.20 | 0.2765 | 0.2129 | 0.5817 | 0.6754 | 24 |
| heldout 18 | baseline | 0.0044 | 4100.8 | 38.06 | 0.1996 | 0.1628 | 0.8835 | 0.8835 | 18 |
| heldout 18 | hardened | 0.0077 | 2331.8 | 38.61 | 0.3811 | 0.3537 | 0.6821 | 0.6821 | 18 |
| repeated 10000 | baseline | 3.7666 | 2654.9 | 38.59 | 0.3213 | 0.0861 | 0.3170 | 9.0659 | 9132 |
| repeated 10000 | hardened | 5.4790 | 1825.2 | 38.70 | 0.4908 | 0.1728 | 0.4767 | 11.7427 | 9132 |
| diverse 10000 | baseline | 5.2757 | 1895.5 | 38.58 | 0.4135 | 0.1947 | 1.2516 | 1.3963 | 9000 |
| diverse 10000 | hardened | 16.2627 | 614.9 | 39.19 | 1.5001 | 0.4231 | 6.6596 | 7.2835 | 9000 |
| maximum 10000 | baseline | 11.5955 | 862.4 | 38.52 | 1.0156 | 1.1444 | 1.3154 | 1.5734 | 10000 |
| maximum 10000 | hardened | 40.8138 | 245.0 | 38.61 | 3.9182 | 1.7381 | 7.0693 | 7.6551 | 10000 |
| diverse 100000 | baseline | 51.6048 | 1937.8 | 40.52 | 0.4050 | 0.1966 | 1.2148 | 1.3154 | 90000 |
| diverse 100000 | hardened | 159.6380 | 626.4 | 41.25 | 1.4686 | 0.4316 | 6.6596 | 6.9300 | 90000 |

Raw artifacts: `/home/psw/detection-hardening-evidence/`. Each run has report.json, categories.csv, report.md and decisions.jsonl. Small sets retain full real findings/evidence. All individual argv invocations are in comparison-commands.jsonl. Generated datasets/reports are not committed. The exact driver command was:

```bash
python /home/psw/detection-hardening-evidence/run_comparison.py > /home/psw/detection-hardening-evidence/comparison.log 2>&1
python /home/psw/detection-hardening-evidence/summarize.py
```

The driver calls evaluate.py sequentially for both detectors on independent (24), published heldout (18), repeated/diverse/maximum (10K each) and diverse (100K). `--cases` is explicit; other config defaults are recorded in each JSON report. The source and corpus digests allow exact verification. Twenty-two raw-source match capsules across the hardened small-set reports were rechecked against their original description strings.

Additional exact verification commands:

```bash
docker run --rm --network=none --memory=256m --memory-swap=256m --cpus=0.5 --user=65534:65534 --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=128 --tmpfs /tmp:rw,nosuid,size=128m -v /home/psw/auditforge-detection-hardening:/source:ro -e PYTHONDONTWRITEBYTECODE=1 -e OLLAMA_TIMEOUT_SECONDS=1 auditforge-detection-tests:v1 sh -c 'cp -R /source /tmp/repo && cd /tmp/repo && PYTHONPATH=src python -m pytest tests/unit tests/integration tests/benchmarks --ignore=tests/integration/test_mcp_live.py -p no:cacheprovider' > /home/psw/detection-hardening-evidence/container-suite-final.log 2>&1
PYTHONPATH=src /home/psw/detection-hardening-evidence/venv/bin/python -m pytest tests/integration/test_mcp_live.py > /home/psw/detection-hardening-evidence/docker-mcp-live.log 2>&1
git diff --exit-code 52bcef7 -- src/auditforge/core src/auditforge/api src/auditforge/catalog src/auditforge/storage src/auditforge/sandbox src/auditforge/assurance src/auditforge/orchestrator.py dashboard
```

Container image ID: `sha256:c59dc5e109fdfb978966f852d88003380f0be8f006c7c8f866839960f4edfcad`. Image build inputs/logs are retained locally; mcp was pinned to 2.3.0, other test tools were resolved during build. This is not a dependency-lock reproducibility claim.

Files inspected include AGENTS.md, production description analyzer, contracts, orchestrator coverage handling, KOALA runner, relevant unit/integration/benchmark tests, and pyproject.toml. Changed files only: description.py, new description_text.py, new test_description_hardening.py, benchmarks/detection_hardening/{evaluation_v1.json,evaluate.py}, and this document. Frozen contracts/API/UI/catalog/storage/sandbox/KOALA/orchestrator and AttackLab branch remain unchanged.

Implementation CI passed Python 3.11 and 3.12: https://github.com/Pswaikar1742/AuditForge/actions/runs/38886344807 . Final documentation revision CI is linked in the PR handoff. Draft PR destination: develop; no merge.

Next work requires separate review: reduce negated-adoption false abstentions with fresh adversarial quotation tests; improve unknown attack-family coverage using independently reviewed new data; profile mapping/evidence overhead without weakening original-source attribution; consider a supervised semantic worker for hard wall-time enforcement. Do not tune on family-challenge-v1 and continue calling it unseen.


The live KOALA test subsequently passed outside the container using the installed KOALA CLI, this clone's model cards and a separate `/home/psw/detection-hardening-evidence/koala-isolated-cache`. Actual output was `. [100%]`, exit 0, for the single existing live test. Command:

```bash
PYTHONPATH=src python /home/psw/detection-hardening-evidence/live_koala.py > /home/psw/detection-hardening-evidence/koala-live.log 2>&1
```

The harness changes only process-local cache paths and the model-card directory, then invokes the existing `tests/integration/test_koala_live.py`. No shared model-assurance history is overwritten and no runtime model probes occur. Existing integration tests have therefore all executed successfully across the constrained-container and dedicated live-test runs.
