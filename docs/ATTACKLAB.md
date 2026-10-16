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

## Phase 2 evaluation protocol

Results schema v2 adds `diversity`, `techniques`, `input_sizes`, `rates`, and `uncertainty`.
Existing repeated generation is unchanged (`--workload repeated`, still default).
`--workload diverse` combines operation, object, scope, instruction wording, encoding/wrapper,
size and seeded choices across nine techniques. Record identifiers ensure content uniqueness;
100K unique bytes does **not** mean 100K independent attack concepts. Every tenth record is
intentionally oversized. `--workload maximum` pads every canonical record to the configured
maximum (at least 1024 bytes), without oversized cases. `--workload heldout` evaluates the
fixed 18-case heldout-v1 set once, irrespective of `--cases`; it is not repeated to inflate counts.

Heldout labels and explicit intent rationales were author-reviewed before execution. There is
no independent human review claim. No detector rules or thresholds are tuned in this workstream.
The fixed set and all results are now public; future detector tuning must use a fresh held-out set.

Exact unique payload and successfully evaluated unique payload counts use SHA-256 membership
in a temporary SQLite file, fixed 2 MiB page cache, and bounded categories/techniques/size bands.
Temporary disk grows with distinct payload count; RAM does not store an unbounded hash set.
Duplicate ratio uses hashable submissions; unserializable records remain errors outside that
ratio. Disk I/O is included in processing time, final index aggregation/export is excluded.
Cache remains a separate bounded LRU; unique evaluated counts do not count repeat calls after eviction.

Rates exclude errors/skips from accuracy denominators. Technique breakdown distinguishes quoted
documentation false positives and Unicode/whitespace/formatting false negatives. Size strata use
whole canonical input bytes. Confidence intervals are explicitly unavailable: all workloads are
finite designed censuses with dependent templates, not probability samples of real-world inputs.
Adding binomial intervals would produce unjustified certainty. F1 uncertainty is likewise unclaimed.

The opt-in matrix runs 1K/10K/100K, cache off/on, for repeated/diverse/maximum in separate sequential
processes. The maximum workload uses **8192 bytes as its configured bound**, not the absolute 16 MiB
supported ceiling. Diverse uses the same 8192-byte inspection bound with requested sizes 256/1024/8192;
10% intentionally exceed it. Repeated retains its original sizes and 131072-byte limit. Results are
workload-specific; different size mixes prevent attributing every performance difference to diversity.
No benchmark invokes a target process, Docker, network, semantic model, or RAG.

## Phase 2 executed results

Measured implementation: `d865165b4380f4fc842fba68900665bcae32fe1e` (all 19 processes recorded a clean tree). Local artifacts: `/home/psw/attacklab-phase2/`.

Exact commands:

```bash
PYTHONPATH=src python -m pytest tests/unit/test_attacklab.py tests/unit/test_contracts.py tests/benchmarks/test_benchmark_targets.py > /home/psw/attacklab-phase2/tests.log 2>&1
PYTHONPATH=src python -m benchmarks.attacklab.matrix --output /home/psw/attacklab-phase2/matrix > /home/psw/attacklab-phase2/matrix.log 2>&1
python /home/psw/attacklab-phase2/summarize.py
git diff --exit-code origin/main -- src dashboard tests/benchmarks
```

Every individual invocation is recorded verbatim as argv JSON in `matrix/commands.jsonl`; per-run raw stdout/stderr is in `matrix/<run>.log`. No datasets or full generated reports are committed.

Actual local pytest output: `42 passed, 967 warnings in 5.90s` (pytest-asyncio deprecations). Matrix: 19/19 exit 0; cached/uncached totals, accuracy, technique/size results and exact cardinalities agree at every scale.

| Workload | Cases | Cache | Runtime s | Submissions/s | RSS MiB | Mean ms | p50 ms | p95 ms | p99 ms | Detector calls |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| repeated | 1000 | False | 0.236 | 4229.5 | 37.88 | 0.2177 | 0.0764 | 0.2129 | 7.1400 | 914 |
| repeated | 1000 | True | 0.094 | 10674.2 | 37.83 | 0.0759 | 0.0460 | 0.1082 | 0.6299 | 27 |
| repeated | 10000 | False | 3.039 | 3290.7 | 38.07 | 0.2838 | 0.0764 | 0.2151 | 8.7993 | 9132 |
| repeated | 10000 | True | 0.806 | 12405.4 | 38.07 | 0.0618 | 0.0465 | 0.0645 | 0.6237 | 27 |
| repeated | 100000 | False | 30.216 | 3309.5 | 38.05 | 0.2820 | 0.0772 | 0.2151 | 8.7993 | 91306 |
| repeated | 100000 | True | 7.772 | 12866.1 | 38.08 | 0.0593 | 0.0451 | 0.0764 | 0.6237 | 27 |
| diverse | 1000 | False | 0.487 | 2052.5 | 37.69 | 0.4143 | 0.1890 | 1.2392 | 1.3154 | 900 |
| diverse | 1000 | True | 0.487 | 2053.2 | 39.14 | 0.4128 | 0.1928 | 1.2027 | 1.2895 | 900 |
| diverse | 10000 | False | 4.712 | 2122.0 | 38.06 | 0.3984 | 0.1890 | 1.2148 | 1.3154 | 9000 |
| diverse | 10000 | True | 4.714 | 2121.3 | 45.25 | 0.3986 | 0.1909 | 1.2027 | 1.3154 | 9000 |
| diverse | 100000 | False | 47.746 | 2094.4 | 40.07 | 0.4039 | 0.1928 | 1.2148 | 1.3419 | 90000 |
| diverse | 100000 | True | 47.916 | 2087.0 | 47.70 | 0.4046 | 0.1966 | 1.2148 | 1.3154 | 90000 |
| maximum | 1000 | False | 1.135 | 880.7 | 37.42 | 1.0448 | 1.1444 | 1.3963 | 2.0584 | 1000 |
| maximum | 1000 | True | 1.080 | 926.1 | 39.33 | 0.9950 | 1.1218 | 1.3024 | 1.3553 | 1000 |
| maximum | 10000 | False | 10.657 | 938.3 | 38.00 | 0.9838 | 1.1218 | 1.2767 | 1.3154 | 10000 |
| maximum | 10000 | True | 10.779 | 927.7 | 45.38 | 0.9943 | 1.1330 | 1.2895 | 1.3419 | 10000 |
| maximum | 100000 | False | 107.722 | 928.3 | 39.78 | 0.9944 | 1.1330 | 1.3024 | 1.3419 | 100000 |
| maximum | 100000 | True | 108.795 | 919.2 | 46.95 | 1.0027 | 1.1330 | 1.3024 | 1.3553 | 100000 |

100K quality (identical with caching off/on):

| Workload | Unique / evaluated | Duplicate ratio | TP | TN | FP | FN | Precision | Recall | F1 | FPR | FNR | Error rate | Unassessed rate |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| repeated | 29 / 27 | 0.99971 | 26087 | 52175 | 4348 | 8696 | 0.85714 | 0.74999 | 0.79999 | 0.07692 | 0.25001 | 0.08694 | 0.08694 |
| diverse | 100000 / 90000 | 0.00000 | 30000 | 10000 | 10000 | 40000 | 0.75000 | 0.42857 | 0.54545 | 0.50000 | 0.57143 | 0.00000 | 0.10000 |
| maximum | 100000 / 100000 | 0.00000 | 33333 | 11112 | 11111 | 44444 | 0.75000 | 0.42857 | 0.54545 | 0.49998 | 0.57143 | 0.00000 | 0.00000 |

Held-out actual report excerpts:

```json
{
  "totals": {
    "submitted": 18,
    "processed": 18,
    "errors": 0,
    "skipped": 0,
    "samples": 14
  },
  "accuracy": {
    "tp": 5,
    "tn": 4,
    "fp": 3,
    "fn": 6,
    "precision": 0.625,
    "recall": 0.45454545454545453,
    "false_positive_rate": 0.42857142857142855,
    "false_negative_rate": 0.5454545454545454,
    "f1": 0.5263157894736842
  },
  "diversity": {
    "unique_payloads": 18,
    "unique_evaluated_payloads": 18,
    "hashable_submissions": 18,
    "duplicate_ratio": 0.0,
    "cardinality_method": "exact disk-backed SHA-256 membership; not an in-memory set",
    "temporary_disk_bytes": 8192
  }
}
```

Repeated caching avoids detector calls; diverse and maximum have no hits and pay cache-management costs. Single-run timing differences are not statistically established speed regressions. All unique counts measure bytes, not independently sampled attack concepts. Input sizes, per-technique confusion matrices and detector-only timing are in each report. Peak RSS includes interpreter imports. Temporary unique-index disk usage is reported separately and grows with unique content. No confidence intervals or real-world detection claims are inferred.

CI implementation revision: GitHub Actions Python 3.11 and 3.12 passed on push and PR (runs 38883211292 and 38883216562). Final documentation revision status is reported in the PR handoff.
