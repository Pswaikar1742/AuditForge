"""Stable aggregate artifacts for future UI ingestion."""
import csv
import json
from pathlib import Path


def export(result, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / "report.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    fields = ["category", "submitted", "processed", "errors", "skipped", "tp", "tn", "fp", "fn", "precision", "recall", "false_positive_rate", "false_negative_rate", "f1"]
    with (output / "categories.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({"category": name, **row} for name, row in result["categories"].items())
    lines = ["# AttackLab synthetic benchmark", "", "This measures deterministic description rules, not production readiness or exploitability.", "", "## Totals", "", "```json", json.dumps(result["totals"], indent=2), "```", "", "## Accuracy", "", "```json", json.dumps(result["accuracy"], indent=2), "```", "", "## Performance", "", "```json", json.dumps(result["performance"], indent=2), "```", "", "## Deduplication", "", "```json", json.dumps(result["deduplication"], indent=2), "```", "", "## Limitations", ""]
    lines.extend("- " + item for item in result["limitations"])
    lines.extend(["", "Full configuration, environment, detector version and per-category metrics: report.json."])
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
