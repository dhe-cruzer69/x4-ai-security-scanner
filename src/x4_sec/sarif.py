"""SARIF 2.1.0 export."""
from __future__ import annotations

import json
from .scanner import Finding


def to_sarif(findings: list[Finding]) -> str:
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.rule,
                "level": {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(
                    f.severity, "warning"
                ),
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "x4-ai-security-scanner", "version": "0.1.0"}},
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
