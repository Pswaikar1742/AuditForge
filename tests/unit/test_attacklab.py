"""Fast tests use the real production deterministic analyzer; no target execution."""
from dataclasses import replace
import csv
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from benchmarks.attacklab.corpus import SCENARIOS, encode, generate
from benchmarks.attacklab.runner import Config, Latency, accuracy, run
from benchmarks.attacklab.report import export
from benchmarks.attacklab.__main__ import main


def test_reproducibility():
    assert list(generate(100, 42)) == list(generate(100, 42))
    assert list(generate(100, 42)) != list(generate(100, 43))


def test_ground_truth_and_streaming():
    corpus = generate(10**12)
    assert iter(corpus) is corpus
    rows = [next(corpus) for _ in SCENARIOS]
    assert len({r.case_id for r in rows}) == len(SCENARIOS)
    assert {r.category for r in rows} == {'benign', 'explicit', 'contextual', 'formatting', 'invalid', 'large'}
    assert rows[6].ground_truth is True
    assert rows[10].ground_truth is False
    assert rows[19].ground_truth is None
    assert all(r.size_bytes == len(encode(r.synthetic_input)) for r in rows)


def test_deduplication_and_bounded_cache():
    plain = run(Config(cases=100))
    cached = run(Config(cases=100, deduplicate=True))
    assert plain['accuracy'] == cached['accuracy']
    assert cached['deduplication']['hits'] > 0
    assert cached['deduplication']['detector_calls'] < plain['deduplication']['detector_calls']
    bounded = run(Config(cases=100, deduplicate=True, cache_entries=2))
    assert bounded['deduplication']['resident_entries'] <= 2
    assert bounded['deduplication']['evictions'] > 0


def test_accuracy():
    result = accuracy(dict(tp=3, tn=6, fp=2, fn=1))
    assert result['precision'] == .6
    assert result['recall'] == .75
    assert result['false_positive_rate'] == .25
    assert result['false_negative_rate'] == .25
    assert result['f1'] == pytest.approx(2 / 3)
    assert accuracy({})['precision'] is None
    assert accuracy({})['recall'] is None
    assert accuracy({})['f1'] is None
    assert run(Config(cases=0))['performance']['processing_latency']['p95_ms'] is None


def test_long_and_malformed():
    rows = list(generate(23, sizes=(65536,)))
    assert len(rows[21].synthetic_input['description'].encode()) == 65536
    result = run(Config(max_input_bytes=1024), [rows[21], rows[19], rows[20], {}, replace(rows[0], size_bytes=0)])
    assert result['totals']['skipped'] == 1
    assert result['totals']['errors'] == 4
    assert result['accuracy']['false_negative_rate'] is None
    assert run(Config(), [rows[21]])['accuracy']['tp'] == 1


def test_real_analyzer_clean_injected_and_evidence(monkeypatch):
    import urllib.request
    monkeypatch.setattr(urllib.request, 'urlopen', lambda *a, **kw: pytest.fail('network called'))
    rows = list(generate(23))
    samples = []
    result = run(Config(), [rows[0], rows[6]], sample=samples.append)
    assert result['accuracy']['tp'] == result['accuracy']['tn'] == 1
    assert samples[0]['findings'][0]['rule_id'] == 'DESC-INJECT-001'
    assert samples[0]['evidence'][0]['raw_data']['matched_string'] == 'Ignore previous instructions'


def test_outputs_and_cli(tmp_path):
    assert main(['--cases', '23', '--seed', '42', '--batch-size', '5', '--samples', '5', '--output', str(tmp_path)]) == 0
    report = json.loads((tmp_path / 'report.json').read_text())
    assert report['totals']['submitted'] == 23
    assert report['totals']['errors'] == 2
    assert len(list(csv.DictReader((tmp_path / 'categories.csv').open()))) == 6
    assert 'not production readiness' in (tmp_path / 'report.md').read_text()
    assert len((tmp_path / 'run.jsonl').read_text().splitlines()) <= 5
    assert main(['--cases', '1', '--output', str(tmp_path)]) == 2
    assert main(['--cases', '23', '--strict', '--output', str(tmp_path / 'strict')]) == 1


def test_completion_and_progress():
    progress = []
    result = run(Config(cases=101, batch_size=10), progress=progress.append)
    assert progress == list(range(10, 101, 10)) + [101]
    t = result['totals']
    assert t['submitted'] == t['processed'] + t['errors'] + t['skipped'] == 101
    assert sum(result['accuracy'][k] for k in ('tp', 'tn', 'fp', 'fn')) == t['processed']


def test_histogram():
    hist = Latency()
    for i in range(1, 101):
        hist.add(i / 1000)
    result = hist.report()
    assert 95 <= result['p95_ms'] <= 96
    assert result['average_ms'] == pytest.approx(50.5)


@pytest.mark.parametrize('kwargs', [{'batch_size': 0}, {'cache_entries': -1}, {'max_input_bytes': 2}, {'sizes': (20_000_000,)}])
def test_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        Config(**kwargs)


def test_resource_limited_execution(tmp_path):
    # Controlled benchmark child only, not an MCP target. Linux memory/CPU limits.
    script = '''import resource
resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
from benchmarks.attacklab.runner import Config, run
r = run(Config(cases=1000, batch_size=7, deduplicate=True, cache_entries=32))
assert r['totals']['submitted'] == 1000
assert r['deduplication']['resident_entries'] <= 32
print(r['performance']['peak_rss_bytes'])
'''
    child = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=25, env=os.environ.copy())
    assert child.returncode == 0, child.stderr
    assert int(child.stdout.strip()) < 256 * 1024 * 1024


def test_diverse_reproducibility_and_parameters():
    from benchmarks.attacklab.workloads import workload
    a = list(workload(Config(workload='diverse', cases=100, sizes=(1024,))))
    assert a == list(workload(Config(workload='diverse', cases=100, sizes=(1024,))))
    assert a != list(workload(Config(workload='diverse', cases=100, seed=43, sizes=(1024,))))
    assert len({encode(c.synthetic_input) for c in a}) == 100
    assert len({c.expected_technique for c in a}) == 9
    assert sum(c.size_bytes > 131072 for c in a) == 10
    assert all(c.size_bytes == len(encode(c.synthetic_input)) for c in a)


def test_exact_unique_evaluated_counts_and_strata():
    rows = list(generate(23))
    r = run(Config(), [rows[0], rows[0], rows[6], rows[19]])
    assert r['diversity']['unique_payloads'] == 3
    assert r['diversity']['unique_evaluated_payloads'] == 2
    assert r['diversity']['duplicate_ratio'] == .25
    assert r['rates']['error_rate'] == .25
    for field in ('techniques', 'input_sizes'):
        assert sum(x['submitted'] for x in r[field].values()) == 4
        assert sum(x['tp'] for x in r[field].values()) == 1
    assert r['uncertainty']['confidence_intervals'] is None


def test_maximum_exact_bounds_and_heldout():
    from benchmarks.attacklab.workloads import workload
    from benchmarks.attacklab.heldout import REVIEWED
    config = Config(workload='maximum', cases=27, max_input_bytes=8192)
    assert all(c.size_bytes == 8192 for c in workload(config))
    assert run(config)['totals']['skipped'] == 0
    result = run(Config(workload='heldout'))
    assert result['totals']['submitted'] == len(REVIEWED) == 18
    assert result['diversity']['unique_payloads'] == 18
    assert all(rationale for _, _, _, rationale in REVIEWED)
    assert result['totals']['errors'] == 0


def test_unique_disk_cleanup_and_bounds():
    from benchmarks.attacklab.quality import UniqueCounts
    unique = UniqueCounts()
    directory = unique.path.parent
    try:
        for i in range(1000):
            unique.add(i.to_bytes(32))
        assert unique.db.execute('PRAGMA cache_size').fetchone()[0] == -2048
        assert unique.report(1000)['unique_payloads'] == 1000
    finally:
        unique.close()
    assert not directory.exists()


def test_diverse_bounded_execution():
    script = '''import resource
resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024, 512*1024*1024))
resource.setrlimit(resource.RLIMIT_CPU, (15,15))
from benchmarks.attacklab.runner import Config,run
r=run(Config(workload='diverse',cases=1000,max_input_bytes=8192,sizes=(1024,),deduplicate=True,cache_entries=32))
assert r['diversity']['unique_payloads']==1000
assert r['diversity']['unique_evaluated_payloads']==900
assert r['deduplication']['resident_entries']<=32
print(r['performance']['peak_rss_bytes'])
'''
    child = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=25)
    assert child.returncode == 0, child.stderr
    assert int(child.stdout.strip()) < 256 * 1024 * 1024
