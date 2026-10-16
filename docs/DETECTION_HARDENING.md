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
