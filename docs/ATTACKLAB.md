# AttackLab: synthetic adversarial corpus and benchmark engine

AttackLab exercises `DescriptionAnalyzer(use_llm=False)` and `ToolRecord` read-only.
It does not execute MCP servers, use Docker, call Ollama, or make network requests.
Results measure synthetic description-rule classification, not exploitability or production readiness.

## Run

From the repository root with Python >=3.11 and existing AuditForge dependencies
(`pydantic`, `python-dotenv`; `pytest` for tests) available:

```bash
export PYTHONPATH="$PWD/src${PYTHONPATH:+:$PYTHONPATH}"
python -m benchmarks.attacklab --cases 100 --seed 42 --batch-size 25 --samples 20 --output /tmp/attacklab-smoke
python -m benchmarks.attacklab --cases 1000 --seed 42 --batch-size 1000 --output /tmp/attacklab-1k
python -m benchmarks.attacklab --cases 100000 --seed 42 --batch-size 1000 --output /tmp/attacklab-100k
python -m benchmarks.attacklab --cases 100000 --seed 42 --batch-size 1000 --deduplicate --output /tmp/attacklab-100k-dedup
python -m pytest tests/unit/test_attacklab.py tests/unit/test_contracts.py tests/benchmarks/test_benchmark_targets.py
```

The suggested `python -m benchmarks.attacklab` invocation works with AuditForge installed
from this checkout too. Explicit PYTHONPATH prevents accidentally importing another worktree.
Use a fresh output directory: an existing `run.jsonl` is never overwritten. Generated artifacts
belong outside Git. No default CI test runs 100,000 cases.

Options: `--cases`, `--seed`, `--batch-size`, `--max-input-bytes` (default 131072),
`--payload-sizes` (comma-separated description byte sizes, default 256,1024,8192,65536),
`--deduplicate`, `--cache-entries` (default 4096), `--samples` (default 0, maximum 1000),
`--output`, `--strict`. Payload sizes and input limit are capped at 16 MiB;
larger-than-default stress cases require explicit size arguments. Input limits cover the
whole canonical JSON record, so description padding alone is smaller than `size_bytes`.
Oversized inputs are SKIPPED without truncation. Malformed records are errors, never negatives.

Exit codes: 0 = benchmark completed (may include expected malformed-record errors),
1 = completed with errors/skips under `--strict`, 2 = configuration/output/runtime setup failure,
130 = interrupted. Interrupted runs retain samples but have no complete aggregate report.
Accuracy regressions do not change the exit code: no unsupported quality threshold is implied.

## Corpus and intended outcomes

Generation v1 cycles through 23 independently labelled scenarios. A seeded RNG chooses large
payload sizes. IDs are unique per run; duplicate content intentionally has different IDs.
Each frozen Case records ID, category, synthetic input, intended label, technique, seed,
canonical input byte size and generation version. Labels express scenario intent, not a
rule-derived verdict. Invalid cases have null truth and are excluded from classification.

Categories cover benign reading, conversion, time, listing, Git subprocess use and honest writes;
explicit overrides, authority spoofing, system delimiters and synthetic secret disclosure;
contextual quotations and credential management; Unicode, whitespace, JSON text, empty text,
duplicate JSON metadata; malformed descriptions/schemas; and padded large inputs.
Duplicate JSON keys are preserved inside description text, not lost through Python dict parsing.
No real credentials, exfiltration endpoints or executable attack payloads are generated.

Expected: ordinary benign cases should be negative; direct injections positive; invalid records
unassessed. Contextual quotations and Unicode/whitespace variants intentionally challenge the
existing rules. Actual outcomes must be read from the measured reports. An empty description
is a valid negative *rule evaluation*, never proof of safety. Annotations are supplied but the
baseline analyzer does not inspect their semantics.

## Bounded execution and metrics

Generation and evaluation are lazy. Batches bound progress intervals; even a batch is never
materialized. Memory is independent of total case count: one bounded input, fixed six-category
counters, two 4096-bin histograms and optional bounded LRU cache. Cache keys hash the complete
canonical input, including schema and annotations. Cache values retain original production
findings/evidence, so reused results preserve their source. No persistent cross-version cache
exists. Evictions can cause repeated evaluation; hits count avoided detector calls rather than
global unique content. Corpus repetition is substantial by design, so cache speedups do not
predict arbitrary customer workloads.

Processing latency includes validation, ToolRecord construction, hashing and detector/cache work
for all submissions. Detector latency times only actual analyze_tool calls, including failed calls.
End-to-end throughput includes generation, sample serialization and progress callbacks but excludes
imports, environment collection and final report export. Both submitted and successfully processed
throughput are reported. Quantiles are logarithmic histogram upper-bound estimates (~1% resolution),
not exact retained samples. Peak RSS is the process-lifetime high-water mark including imports;
Linux reports KiB and macOS bytes, normalized to bytes. Run each measurement in a fresh process.

Errors/skips never contribute to TP/TN/FP/FN. Rates with zero denominators are JSON null, CSV empty.
FNR = FN/(TP+FN). Accuracy is case-weighted, including duplicates; no claim of independent statistical
samples is made. Size validation serializes one record before checking its bound; the public Python
iterator API is for trusted bounded corpus producers, not an untrusted ingestion security boundary.
Schema validation checks benchmark object shape, not full JSON Schema metaschema correctness.

A controlled test child enforces 512 MiB address space, 15 CPU seconds and a 25-second wall timeout,
and checks peak RSS below 256 MiB. This is a benchmark process, not target execution or isolation.
An initial 256 MiB address-space test failed during imports on Python 3.14, whose empty interpreter
already reserved about 237 MiB virtual memory; virtual address size is not resident memory.

## Result interface

`report.json` uses `schema_version: attacklab.results.v1` and contains configuration, environment,
totals, accuracy, categories, performance, deduplication and limitations. Environment records Python,
platform, Git HEAD/dirty flag, imported detector path and SHA-256 of the complete detector module
(including its regex table). This hash versions the detector source, not the entire dependency tree.
`categories.csv` contains category totals and confusion matrices/rates; `report.md` summarizes the
run; `run.jsonl` contains up to `--samples` actual findings with linked unedited EvidenceRecords,
false negatives and errors. Zero matches are not represented as verified security findings.
Reports are suitable for later UI ingestion without changing any API or frozen contract.

## Scope and next improvements

No production source, API, UI, history, approvals, contracts or existing tests are changed.
No semantic-model benchmark is implemented. No worker queue or parallel inference is added.
Expand beyond template repetition with reviewed held-out scenarios, semantic samples with explicit
unavailable coverage, dependency-lock provenance, per-size metrics and cancellable checkpoint reports.
The current baseline detector's contextual false positives and obfuscated false negatives require a
separate scanner-owned workstream; AttackLab intentionally does not patch those rules.

## Executed acceptance evidence (2026-10-16)

Measured implementation commit: `1e7dea1bcbdc06bb82eb3eaf77963bf31830c425` (clean checkout).
Stable parent: `c97baf48b0e9efcecb90e3b521de43403354bcaf`. Python 3.14.7, Nobara Linux x86_64.
Raw logs and JSON/CSV/Markdown artifacts: `/home/psw/attacklab-evidence/` (not committed).

Exact executed commands from `/home/psw/auditforge-attacklab`:

```bash
export PYTHONPATH="$PWD/src"
python -m benchmarks.attacklab --cases 100 --seed 42 --batch-size 25 --samples 20 --output /home/psw/attacklab-evidence/smoke > /home/psw/attacklab-evidence/smoke.log 2>&1
python -m benchmarks.attacklab --cases 1000 --seed 42 --batch-size 1000 --output /home/psw/attacklab-evidence/1k > /home/psw/attacklab-evidence/1k.log 2>&1
python -m benchmarks.attacklab --cases 100000 --seed 42 --batch-size 1000 --output /home/psw/attacklab-evidence/100k > /home/psw/attacklab-evidence/100k.log 2>&1
python -m benchmarks.attacklab --cases 100000 --seed 42 --batch-size 1000 --deduplicate --output /home/psw/attacklab-evidence/100k-dedup > /home/psw/attacklab-evidence/100k-dedup.log 2>&1
PYTHONPATH=src python -m pytest tests/unit/test_attacklab.py tests/unit/test_contracts.py tests/benchmarks/test_benchmark_targets.py > /home/psw/attacklab-evidence/tests.log 2>&1
git diff --name-only origin/main -- src dashboard tests/benchmarks
```

All four benchmark commands exited 0. Scope diff output was empty. Actual pytest summary:

```text
37 passed, 782 warnings in 4.66s
```

Warnings are existing pytest-asyncio deprecations under Python 3.14. Initial resource test attempt: `1 failed, 19 passed, 645 warnings in 0.53s`; failure was `MemoryError` during Pydantic import under a 256 MiB virtual-address limit, addressed as described above.

| Run | Submitted | Assessed | Invalid errors | Runtime s | Submitted/s | Detector calls/s | Peak RSS MiB | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| smoke | 100 | 92 | 8 | 0.012497 | 8001.95 | 16467.85 | 34.87 | 4 | 8 |
| 1k | 1000 | 914 | 86 | 0.211190 | 4735.07 | 6010.45 | 36.35 | 44 | 86 |
| 100k | 100000 | 91306 | 8694 | 28.520642 | 3506.23 | 4153.81 | 36.14 | 4348 | 8696 |
| 100k-dedup | 100000 | 91306 | 8694 | 5.794038 | 17259.12 | 1403.03 | 36.23 | 4348 | 8696 |

100K without dedup: TP 26,087; TN 52,175; precision 85.714%; recall 74.999%; FPR 7.692%; FNR 25.001%; F1 0.799994. Invalid-input rate 8.694%; zero skips and no observed detector failures. Invalid errors are all in the invalid category, not failed negative classifications.

100K processing latency: average 0.265914 ms, p50 0.055573 ms, p95 0.200597 ms, p99 8.799290 ms. Detector-only average 0.240743 ms, p95 0.169379 ms. Deduplicated processing average 0.040868 ms, p95 0.049811 ms. Dedup has 91,279 hits, 27 real calls and zero evictions; confusion matrices are identical.

Expected versus actual: all explicit injections and large embedded injections matched; all ordinary benign scenarios were negative. Quoted attack documentation produced the false positives; full-width Unicode and whitespace-obfuscated directives produced the false negatives. These are measured detector limitations, not hidden benchmark failures.

Files inspected: root AGENTS.md, pyproject.toml, src/auditforge/analyzers/description.py, src/auditforge/core/contracts.py, src/auditforge/config.py, and relevant test discovery. Files created: benchmarks/attacklab/{__init__,__main__,corpus,runner,report}.py, tests/unit/test_attacklab.py, docs/ATTACKLAB.md.

Review destination: draft PR against **main**, per the explicit AttackLab workstream instruction overriding the older general develop-only handoff rule. No merge performed. No production files changed. Single-run timings are workstation measurements, not controlled comparative performance claims.
