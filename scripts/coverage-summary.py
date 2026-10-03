"""Render native coverage totals as a GitHub Actions job summary."""

import json
import sys
from pathlib import Path

kind, report_path = sys.argv[1:]
report = json.loads(Path(report_path).read_text())
if kind == "rust":
    totals = report["data"][0]["totals"]
    metrics = ("lines", "functions", "regions")
    percent_key, count_key = "percent", "count"
elif kind == "web":
    totals = report["total"]
    metrics = ("lines", "branches", "functions", "statements")
    percent_key, count_key = "pct", "total"
else:
    raise SystemExit(f"Unknown coverage report kind: {kind}")

print(f"### {kind.capitalize()} coverage\n")
print("| Metric | Coverage | Covered / total |")
print("| --- | ---: | ---: |")
for metric in metrics:
    values = totals[metric]
    print(
        f"| {metric.capitalize()} | {values[percent_key]:.2f}% "
        f"| {values['covered']} / {values[count_key]} |"
    )
print("\nDownload this job's coverage artifact for per-file HTML and LCOV reports.")
if kind == "rust":
    print("\nProduction-only Rust coverage reports lines/functions/regions; tests and test helpers are excluded.")
