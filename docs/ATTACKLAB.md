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
