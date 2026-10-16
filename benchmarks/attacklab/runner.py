"""Bounded streaming metrics around the real deterministic analyzer."""
from collections import Counter, OrderedDict
from dataclasses import asdict, dataclass
import hashlib
import inspect
from itertools import islice
import math
import platform
import resource
import subprocess
import sys
import time
from typing import Iterable

from auditforge.analyzers.description import DescriptionAnalyzer
from auditforge.core.contracts import ToolRecord
from .corpus import Case, encode, generate

@dataclass(frozen=True)
class Config:
    cases: int = 1000
    seed: int = 42
    batch_size: int = 1000
    max_input_bytes: int = 131072
    deduplicate: bool = False
    cache_entries: int = 4096
    sizes: tuple[int, ...] = (256, 1024, 8192, 65536)
    sample_limit: int = 100

    def __post_init__(self):
        if not 0 <= self.cases or not 1 <= self.batch_size <= 10000:
            raise ValueError("cases >= 0 and batch size 1..10000 required")
        if not 128 <= self.max_input_bytes <= 16 * 1024 * 1024:
            raise ValueError("max input bytes must be 128..16777216")
        if not 0 <= self.cache_entries <= 100000 or not 0 <= self.sample_limit <= 1000:
            raise ValueError("cache entries 0..100000; sample limit 0..1000 required")
        if not self.sizes or any(s < 128 or s > 16 * 1024 * 1024 for s in self.sizes):
            raise ValueError("payload sizes must be 128..16777216")

class Latency:
    """Fixed 4096-bin logarithmic histogram: approximate upper-bound quantiles."""
    def __init__(self):
        self.bins = [0] * 4096
        self.count = 0
        self.total = 0.0

    def add(self, seconds):
        self.count += 1
        self.total += seconds
        self.bins[min(4095, max(0, math.ceil(math.log1p(seconds * 1e9) / math.log(1.01))))] += 1

    def report(self):
        def percentile(q):
            if not self.count:
                return None
            rank, seen = math.ceil(self.count * q), 0
            for i, count in enumerate(self.bins):
                seen += count
                if seen >= rank:
                    return math.expm1(i * math.log(1.01)) / 1e6
        return {"count": self.count, "average_ms": self.total * 1000 / self.count if self.count else None,
                "p50_ms": percentile(.5), "p95_ms": percentile(.95), "p99_ms": percentile(.99),
                "quantiles": "log histogram upper bounds, ~1% resolution, saturated above ~15 years"}


def accuracy(counts):
    tp, tn, fp, fn = (counts.get(k, 0) for k in ("tp", "tn", "fp", "fn"))
    ratio = lambda a, b: a / b if b else None
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "false_positive_rate": ratio(fp, fp + tn), "false_negative_rate": ratio(fn, fn + tp),
            "f1": ratio(2 * tp, 2 * tp + fp + fn)}


def environment():
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=5, check=True).stdout)
    except (OSError, subprocess.SubprocessError):
        commit, dirty = None, None
    return {"python": sys.version, "platform": platform.platform(), "git_commit": commit,
            "git_dirty": dirty, "detector_path": inspect.getfile(DescriptionAnalyzer),
            "detector_version": hashlib.sha256(inspect.getsource(sys.modules[DescriptionAnalyzer.__module__]).encode()).hexdigest(),
            "semantic_inference": "DISABLED", "runtime_probing": "NOT_PERFORMED"}


def run(config: Config, records: Iterable[Case] | None = None, progress=None, sample=None):
    env = environment()
    analyzer = DescriptionAnalyzer(use_llm=False)
    cache = OrderedDict()
    totals, categories = Counter(), {}
    processing, detector = Latency(), Latency()
    started = time.perf_counter()
    iterator = iter(records if records is not None else generate(config.cases, config.seed, config.sizes))
    # Only bounded iterator slices: never materialize batch_size * payload_size bytes.
    while True:
        batch_count = 0
        for case in islice(iterator, config.batch_size):
            batch_count += 1
            tick = time.perf_counter()
            totals["submitted"] += 1
            category = case.category if isinstance(case, Case) and case.category in {"benign", "explicit", "contextual", "formatting", "invalid", "large"} else "invalid"
            counts = categories.setdefault(category, Counter())
            counts["submitted"] += 1
            status, reason, findings, evidence = "processed", None, [], []
            try:
                if not isinstance(case, Case) or case.ground_truth is not True and case.ground_truth is not False and case.ground_truth is not None:
                    raise ValueError("invalid case or ground-truth label")
                raw = encode(case.synthetic_input)
                if len(raw) != case.size_bytes:
                    raise ValueError("size_bytes mismatch")
                if len(raw) > config.max_input_bytes:
                    status, reason = "skipped", "input exceeds maximum bytes; not inspected"
                else:
                    payload = case.synthetic_input
                    if not isinstance(payload, dict) or not isinstance(payload.get("description"), str) or not isinstance(payload.get("input_schema"), dict):
                        raise ValueError("description must be text and input_schema an object")
                    if payload["input_schema"].get("type") != "object":
                        raise ValueError("benchmark requires object input schema")
                    tool = ToolRecord.model_validate(payload)
                    if case.ground_truth is None:
                        status, reason = "skipped", "no assessable ground truth"
                    else:
                        key = hashlib.sha256(raw).digest()
                        if config.deduplicate and key in cache:
                            totals["cache_hits"] += 1
                            findings, evidence = cache.pop(key)
                            cache[key] = (findings, evidence)
                        else:
                            dt = time.perf_counter()
                            try:
                                findings, evidence = analyzer.analyze_tool(tool)
                            finally:
                                detector.add(time.perf_counter() - dt)
                            if config.deduplicate and config.cache_entries:
                                cache[key] = (findings, evidence)
                                if len(cache) > config.cache_entries:
                                    cache.popitem(last=False)
                                    totals["cache_evictions"] += 1
                        evidence_ids = {ev.evidence_id for ev in evidence}
                        if any(not f.evidence_ids or not set(f.evidence_ids) <= evidence_ids for f in findings):
                            raise ValueError("detector finding lacks linked evidence")
                        bucket = ("tp" if findings else "fn") if case.ground_truth else ("fp" if findings else "tn")
                        counts[bucket] += 1
                        totals[bucket] += 1
            except Exception as exc:
                status, reason = "errors", f"{type(exc).__name__}: {exc}"
            totals[status] += 1
            counts[status] += 1
            processing.add(time.perf_counter() - tick)
            if sample and totals["samples"] < config.sample_limit and (status != "processed" or findings or bucket == "fn"):
                sample({"case": asdict(case) if isinstance(case, Case) else repr(case), "status": status,
                        "reason": reason, "findings": [f.model_dump(mode="json") for f in findings],
                        "evidence": [e.model_dump(mode="json") for e in evidence]})
                totals["samples"] += 1
        if progress and batch_count:
            progress(totals["submitted"])
        if not batch_count:
            break
    elapsed = time.perf_counter() - started
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return {"schema_version": "attacklab.results.v1", "configuration": asdict(config), "environment": env,
            "totals": {k: totals[k] for k in ("submitted", "processed", "errors", "skipped", "samples")},
            "accuracy": accuracy(totals),
            "categories": {k: {**{s: v[s] for s in ("submitted", "processed", "errors", "skipped")}, **accuracy(v)} for k, v in categories.items()},
            "performance": {"runtime_seconds": elapsed, "submitted_per_second": totals["submitted"] / elapsed,
                            "processed_per_second": totals["processed"] / elapsed,
                            "detector_calls_per_second": detector.count / detector.total if detector.total else None,
                            "peak_rss_bytes": rss if sys.platform == "darwin" else rss * 1024,
                            "rss_scope": "process lifetime high-water mark including imports",
                            "processing_latency": processing.report(), "detector_latency": detector.report()},
            "deduplication": {"hits": totals["cache_hits"], "evictions": totals["cache_evictions"],
                              "resident_entries": len(cache), "detector_calls": detector.count},
            "limitations": ["Synthetic template accuracy is not real-world exploit detection accuracy.",
                            "No matches means only no deterministic rule match; not verified safe.",
                            "Errors and skips are excluded from classification denominators.",
                            "End-to-end timing includes generation and optional samples, excludes imports and report export."]}
