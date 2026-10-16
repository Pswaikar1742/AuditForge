# AttackLab detection gaps: proposals for scanner owners

This document recommends changes; it does not implement or claim improvements to
DescriptionAnalyzer. Detector source SHA-256 is recorded in every report. No scanner,
API, UI, catalog, evidence contract or AGY worktree change is part of Phase 2.

## Observed evidence and scope

The diverse 100K uncached run assessed 90,000 payloads and skipped 10,000 oversized
inputs. Each assessed technique group has 10,000 cases. Direct overrides, structured
JSON overrides and synthetic secret disclosures all matched. Quoted documentation
produced 10,000 false positives; Unicode, whitespace, Markdown formatting and implicit
authority claims each produced 10,000 false negatives. Ordinary benign operations
produced no false positives. These are outcomes of designed scenario families, not
independent real-world attack trials or proof of exploitability.

Raw aggregate source: `diverse-100000-plain/report.json`, fields `techniques` and
`input_sizes` under `/home/psw/attacklab-phase2/matrix/`. Repeated cases are retained
separately and must not be pooled as independent evidence. Heldout-v1 is a fixed,
author-reviewed challenge set with per-case intent rationale in
`benchmarks/attacklab/heldout.py`; it has not been independently human-reviewed.

## 1. Regex improvements: lexical coverage

Whitespace-separated overrides evade literal-space patterns. Consider bounded whitespace
matching between tokens and explicit Unicode-aware token boundaries. Avoid broad `.*`
expansions and test worst-case runtime on long near-matching negative strings. Add tests
for ordinary prose, quoted examples and punctuation before enabling any new pattern.
Regex expansion alone cannot determine whether quoted instructions are being endorsed.

## 2. Normalization: derived views with original evidence

Full-width letters and zero-width insertions evade the current text view. Evaluate NFKC
normalization and a deliberately limited policy for selected invisible characters.
Markdown decoration also needs a separately tested parsing/normalization strategy.
Preserve original bytes and a mapping from normalized spans back to raw source spans;
findings must quote the original input, never a silently rewritten reconstruction.
Normalization can change meaning in legitimate Unicode text; measure multilingual and
technical-document false positives separately. Do not indiscriminately strip every
non-ASCII character, punctuation mark or delimiter.

## 3. Contextual classification: quotation is not endorsement

The current detector flags explicit educational quotations. For example heldout case
`h1-004` rejects the phrase "system override" as hostile text. Evaluate context signals
such as attribution, negation, quotation boundaries and requested task, with a three-way
result (suspected directive / explanatory quotation / uncertain). Do not globally exempt
quoted text: real instructions can hide in quotes or JSON. Pair documentation negatives
with malicious quoted-command positives. Keep ambiguous cases reviewable and distinguish
rule evidence from an assertion of malicious intent.

## 4. Optional semantic inference: constrained ambiguity review

Implicit authority spoofing can lack all lexical trigger phrases. A separate, capped
semantic evaluation may help review that class and uncertain quotation cases. Compare
it with deterministic-only results on a new frozen test set; record model/version,
latency, cost, false positives, failures and abstentions. Timeouts or unavailable models
must remain unassessed, not safe. Require verbatim evidence and treat target text as
untrusted data. No semantic model or RAG is added to AttackLab. RAG belongs to a separately
evaluated knowledge service and is not an injection safety boundary.

## Acceptance proposal for the scanner workstream

Use the published cases as regression examples, not as a future held-out test after
rule tuning. Have an independent reviewer label new cases before changing rules; split
by attack family/source rather than random template copies. Measure confusion matrices
by technique and size, unassessed rates, bounded worst-case runtime and raw-evidence
fidelity. Choose release thresholds through explicit review instead of inventing them
from this corpus. Re-run benign subprocess, filesystem and credential descriptions
alongside adversarial text. Do not optimize total finding count or claim production
readiness from higher synthetic recall.

## Held-out measured evidence

Measured clean implementation commit: `d865165b4380f4fc842fba68900665bcae32fe1e`.
18/18 unique cases assessed; no errors/skips. TP 5, TN 4, FP 3, FN 6; precision
62.50%, recall 45.45%, F1 0.52632, FPR 42.86%, FNR 54.55%. These are descriptive
fractions of this small designed set; confidence intervals are not justified by a
probability-sampling model. No held-out outcome was used to modify detector rules.

| Case | Intended scenario | Observed outcome | Raw matched quote / missing detection |
|---|---|---|---|
| h1-004 | Reject quoted authority override | FP | `system override` |
| h1-005 | Document delimiter attacks | FP | `<admin>` |
| h1-006 | Explain disclosure risk | FP | `output all environment` |
| h1-011, h1-012 | Tab/newline overrides | FN | No deterministic match |
| h1-013, h1-014 | Full-width/zero-width overrides | FN | No deterministic match |
| h1-015 | Markdown-decorated override | FN | No deterministic match |
| h1-016 | Vendor claims higher authority | FN | No deterministic match |

Actual production findings and linked unedited EvidenceRecords for positive matches,
and original synthetic inputs for missed cases, are retained in
`/home/psw/attacklab-phase2/matrix/heldout-18-plain/run.jsonl`.
False negatives are benchmark outcomes derived from labels and absence of rule matches,
not fabricated security findings or proof of exploit execution.

The complete 1K/10K/100K cached/uncached performance table and exact commands are in
[ATTACKLAB.md](ATTACKLAB.md#phase-2-executed-results). All nine paired runs have identical
accuracy, per-technique/size counts, coverage and cardinality. Production source diffs
remain empty. All performance measurements are single observations on one workstation;
repeat randomized-order trials before attributing small timing differences to caching.
