"""python -m benchmarks.attacklab --cases 100000 --output /tmp/attacklab"""
import argparse
import json
from pathlib import Path
import sys
from .runner import Config, run
from .report import export


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline synthetic MCP description benchmark")
    parser.add_argument("--workload", choices=("repeated", "diverse", "maximum", "heldout"), default="repeated")
    parser.add_argument("--cases", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument("--max-input-bytes", type=int, default=131072)
    parser.add_argument("--payload-sizes", default="256,1024,8192,65536")
    parser.add_argument("--deduplicate", action="store_true")
    parser.add_argument("--cache-entries", type=int, default=4096)
    parser.add_argument("--samples", type=int, default=0, help="Maximum JSONL evidence samples (0..1000)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--strict", action="store_true", help="Exit 1 when any input is errored/skipped")
    args = parser.parse_args(argv)
    try:
        config = Config(workload=args.workload, cases=args.cases, seed=args.seed, batch_size=args.batch_size,
                        max_input_bytes=args.max_input_bytes, deduplicate=args.deduplicate,
                        cache_entries=args.cache_entries, sizes=tuple(map(int, args.payload_sizes.split(','))),
                        sample_limit=args.samples)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        args.output.mkdir(parents=True, exist_ok=True)
        # Exclusive creation protects previous reports and samples from accidental overwrite.
        with (args.output / "run.jsonl").open("x") as stream:
            result = run(config, progress=lambda n: print(f"processed submissions: {n}", file=sys.stderr),
                         sample=(lambda row: stream.write(json.dumps(row, ensure_ascii=False) + "\n")) if args.samples else None)
        export(result, args.output)
        print(json.dumps({"totals": result["totals"], "accuracy": result["accuracy"],
                          "performance": result["performance"], "deduplication": result["deduplication"]}, indent=2))
        return int(args.strict and bool(result["totals"]["errors"] + result["totals"]["skipped"]))
    except KeyboardInterrupt:
        print("Interrupted; report incomplete. Use a new output directory to rerun.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError) as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
