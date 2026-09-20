"""Deterministic rule-based scanner."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Finding:
    severity: str
    rule: str
    file: str
    line: int
    message: str
    confidence: float
    remediation: str


RULES = [
    {
        "id": "X4-CRED-001",
        "severity": "CRITICAL",
        "pattern": re.compile(r"curl\s+[^|\n]*\|\s*(ba)?sh", re.I),
        "message": "Pipe-to-shell pattern (credential/command injection risk)",
        "remediation": "Remove curl|sh; use verified installers",
        "confidence": 0.95,
    },
    {
        "id": "X4-PROMPT-001",
        "severity": "HIGH",
        "pattern": re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.I),
        "message": "Classic prompt-injection phrase",
        "remediation": "Remove or sandbox untrusted instruction text",
        "confidence": 0.9,
    },
    {
        "id": "X4-SECRET-001",
        "severity": "HIGH",
        "pattern": re.compile(r"(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})"),
        "message": "Credential-shaped token",
        "remediation": "Rotate secret; store outside source",
        "confidence": 0.85,
    },
]

SCAN_GLOBS = [
    "**/.claude/**",
    "**/.cursor/**",
    "**/mcp.json",
    "**/mcp.yaml",
    "**/SKILL.md",
    "**/CLAUDE.md",
    "**/AGENTS.md",
    "**/*.sh",
    "**/Dockerfile",
]


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    root = root.resolve()
    files: set[Path] = set()
    for pattern in SCAN_GLOBS:
        files.update(root.glob(pattern))
    for path in sorted(files):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for rule in RULES:
                if rule["pattern"].search(line):
                    findings.append(
                        Finding(
                            severity=rule["severity"],
                            rule=rule["id"],
                            file=str(path.relative_to(root)),
                            line=i,
                            message=rule["message"],
                            confidence=rule["confidence"],
                            remediation=rule["remediation"],
                        )
                    )
    return findings
