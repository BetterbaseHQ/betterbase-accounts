"""Fail if Rust coverage includes tests or inline test modules return."""

import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
report = json.loads(Path(sys.argv[1]).read_text())
problems = []
for data in report["data"]:
    for file in data["files"]:
        path = Path(file["filename"]).resolve()
        relative = path.relative_to(root)
        if (
            path.stem == "tests"
            or path.stem.endswith(("_tests", "test_support"))
            or any(part in ("tests", "examples", "benches") for part in relative.parts)
        ):
            problems.append(f"Test code included in coverage: {path}")
for directory in (root / "crates", root / "bins"):
    for path in directory.rglob("*.rs"):
        if re.search(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{", path.read_text()):
            problems.append(f"Move inline test module to a dedicated *_tests.rs file: {path}")
if problems:
    raise SystemExit("\n".join(problems))
print("Rust coverage contains production files only; no inline test modules found.")
