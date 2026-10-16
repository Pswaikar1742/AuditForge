"""Evaluate real baseline/hardened detectors using unchanged AttackLab Phase 2.

Set PYTHONPATH=src:<independent AttackLab checkout>. Baseline source is exported
from the recorded Git revision, never copied into or merged with AttackLab PR #2.
"""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys

from auditforge.analyzers.description import DescriptionAnalyzer as Hardened
from benchmarks.attacklab.corpus import Case, encode
from benchmarks.attacklab import runner
from benchmarks.attacklab.report import export
from benchmarks.attacklab.workloads import workload

BASELINE_REVISION = '52bcef7631f515ebc939f5e9c6b3d14433718985'
ATTACKLAB_REVISION = '32f0f0bea6bc4352c17f95e1fd00b191492343de'
BASELINE_SOURCE_SHA256 = '8476ef474683b60856dfdffac85ab372264cdb1afe504f57822c78a80c8096d9'


class AbstentionError(RuntimeError):
    """Adapter prevents AttackLab v2 treating unresolved inspection as a negative."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--detector', choices=('baseline', 'hardened'), required=True)
    parser.add_argument('--baseline-source', type=Path)
    parser.add_argument('--workload', choices=('independent', 'heldout', 'repeated', 'diverse', 'maximum'), required=True)
    parser.add_argument('--cases', type=int, default=10000)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.detector == 'baseline':
        if not args.baseline_source:
            parser.error('--baseline-source required for baseline')
        if hashlib.sha256(args.baseline_source.read_bytes()).hexdigest() != BASELINE_SOURCE_SHA256:
            parser.error('baseline source differs from the verified develop detector')
        spec = importlib.util.spec_from_file_location('baseline_description', args.baseline_source)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        detector = module.DescriptionAnalyzer
    else:
        detector = Hardened
    args.output.mkdir(parents=True, exist_ok=False)
    config = runner.Config(workload='heldout' if args.workload == 'independent' else args.workload,
                           cases=args.cases, seed=42, batch_size=1000, deduplicate=False, sample_limit=0,
                           max_input_bytes=8192 if args.workload in ('diverse', 'maximum') else 131072,
                           sizes=(256, 1024, 8192) if args.workload in ('diverse', 'maximum') else (256, 1024, 8192, 65536))
    families, states = defaultdict(Counter), Counter()
    current, corpus_hash = {}, hashlib.sha256()
    if args.workload == 'independent':
        frozen = json.loads(Path(__file__).with_name('evaluation_v1.json').read_text())
        def independent():
            for row in frozen['cases']:
                payload = {'name': 'evaluation_tool', 'description': row['text'], 'input_schema': {'type': 'object'}}
                yield Case(row['id'], 'explicit' if row['label'] else 'benign', payload, row['label'],
                           row['family'], 0, len(encode(payload)), frozen['version'])
        records = independent()
    else:
        records = workload(config)

    def tracked():
        for case in records:
            current['case'] = case
            corpus_hash.update(encode(asdict(case)))
            yield case

    with (args.output / 'decisions.jsonl').open('x') as decisions:
        class CoverageAnalyzer(detector):
            def analyze_tool(self, tool):
                findings, evidence = super().analyze_tool(tool)
                unresolved = any(e.raw_data.get('status') in ('SKIPPED', 'ERROR') for e in evidence)
                case = current['case']
                family = families[case.expected_technique or case.category]
                decision = 'REVIEW_REQUIRED' if unresolved else ('SUSPICIOUS' if findings else 'NO_DETERMINISTIC_INDICATOR')
                states[decision] += 1
                family['submitted'] += 1
                family['labelled_positive' if case.ground_truth else 'labelled_negative'] += 1
                if unresolved:
                    family['abstained'] += 1
                    family['positive_abstentions' if case.ground_truth else 'negative_abstentions'] += 1
                else:
                    bucket = ('tp' if findings else 'fn') if case.ground_truth else ('fp' if findings else 'tn')
                    family[bucket] += 1
                # Full evidence for the small evaluation sets only, not throughput workloads.
                if args.workload in ('independent', 'heldout'):
                    decisions.write(json.dumps({'case': asdict(case), 'decision': decision,
                        'findings': [f.model_dump(mode='json') for f in findings],
                        'evidence': [e.model_dump(mode='json') for e in evidence]}, ensure_ascii=False) + '\n')
                if unresolved:
                    raise AbstentionError('explicit detector coverage abstention; see coverage totals')
                return findings, evidence
        runner.DescriptionAnalyzer = CoverageAnalyzer
        result = runner.run(config, records=tracked())
    source = Path(inspect.getfile(detector))
    result['evaluation'] = {
        'detector': args.detector, 'workload': args.workload,
        'baseline_revision': BASELINE_REVISION, 'attacklab_revision': ATTACKLAB_REVISION,
        'corpus_sha256': corpus_hash.hexdigest(),
        'detector_source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'normalization_source_sha256': hashlib.sha256(Path(inspect.getfile(Hardened)).with_name('description_text.py').read_bytes()).hexdigest() if args.detector == 'hardened' else None,
        'states': dict(states),
        'abstentions': states['REVIEW_REQUIRED'],
        'positive_abstentions': sum(c['positive_abstentions'] for c in families.values()),
        'negative_abstentions': sum(c['negative_abstentions'] for c in families.values()),
        'positive_detection_fraction_including_abstentions': (sum(c['tp'] for c in families.values()) / sum(c['labelled_positive'] for c in families.values())) if sum(c['labelled_positive'] for c in families.values()) else None,
        'errors_excluding_abstentions': result['totals']['errors'] - states['REVIEW_REQUIRED'],
        'families': {name: {**dict(counts), **runner.accuracy(counts)} for name, counts in families.items()},
        'notes': ['AttackLab v2 engine is unchanged; adapter maps explicit detector abstentions to unassessed errors.',
                  'Abstentions are excluded from classification denominators and reported separately, never silently counted as negatives.',
                  'Detector timing includes constant-memory adapter accounting; both versions use the identical adapter.',
                  'Published heldout-v1 is development/regression data, not independent validation.',
                  'family-challenge-v1 was author-labelled and frozen before detector edits; not independently human-reviewed.',
                  'No probability-sampling confidence interval is justified for this designed set.'],
    }
    result['environment']['detector_path'] = str(source)
    result['environment']['detector_version'] = result['evaluation']['detector_source_sha256']
    export(result, args.output)
    print(json.dumps({k: result[k] for k in ('totals', 'accuracy', 'performance', 'evaluation')}, indent=2))


if __name__ == '__main__':
    main()
