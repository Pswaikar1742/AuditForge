"""Opt-in sequential fresh-process scale matrix; never imported by CI tests.

python -m benchmarks.attacklab.matrix --output /tmp/attacklab-phase2
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    commands = args.output / 'commands.jsonl'
    with commands.open('x') as manifest:
        for workload in ('repeated', 'diverse', 'maximum', 'heldout'):
            for n in ((18,) if workload == 'heldout' else (1000, 10000, 100000)):
                for cached in ((False,) if workload == 'heldout' else (False, True)):
                    name = f'{workload}-{n}-' + ('cache' if cached else 'plain')
                    cmd = [sys.executable, '-m', 'benchmarks.attacklab', '--workload', workload,
                           '--cases', str(n), '--seed', '42', '--batch-size', '1000', '--output', str(args.output / name)]
                    if cached:
                        cmd.append('--deduplicate')
                    if workload in ('diverse', 'maximum'):
                        cmd += ['--max-input-bytes', '8192', '--payload-sizes', '256,1024,8192']
                    if workload == 'heldout':
                        cmd += ['--samples', '100']
                    manifest.write(json.dumps(cmd) + '\n')
                    manifest.flush()
                    print('START ' + name, flush=True)
                    with (args.output / (name + '.log')).open('x') as log:
                        result = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT, timeout=1800)
                    if result.returncode:
                        raise SystemExit(f'{name} failed: exit {result.returncode}; see log')
                    print('FINISHED ' + name, flush=True)


if __name__ == '__main__':
    main()
