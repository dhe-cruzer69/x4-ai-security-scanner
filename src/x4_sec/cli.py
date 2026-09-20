"""CLI for x4-sec."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan_path
from .sarif import to_sarif


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="x4-sec")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--sarif", metavar="FILE")
    parser.add_argument("--fail-on", choices=["none", "low", "medium", "high", "critical"], default="critical")
    args = parser.parse_args(argv)

    findings = scan_path(Path(args.path))
    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.severity:8} {f.file}:{f.line}  {f.rule}  {f.message}")
        print(f"findings={len(findings)}")

    if args.sarif:
        Path(args.sarif).write_text(to_sarif(findings), encoding="utf-8")

    order = {"none": -1, "low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold = order[args.fail_on]
    if any(order.get(f.severity.lower(), 0) >= threshold and threshold >= 0 for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
