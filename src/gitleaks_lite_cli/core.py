"""Core, I/O-free scanning logic for gitleaks-lite-cli.

This is a heuristic scanner: everything below is regex pattern-matching
plus a simple Shannon-entropy check on candidate values. It has no
knowledge of any real secret-issuing service and makes no network calls —
it cannot confirm a match is a live, working credential, and it will
produce both false positives (things that merely look like secrets) and
false negatives (real secrets in a shape it doesn't recognize).
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

AWS_ACCESS_KEY_RE = re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
GENERIC_API_KEY_RE = re.compile(
    r"(?i)\bapi[_-]?key\b\s*[:=]\s*[\'\"]?([A-Za-z0-9_\-]{16,64})[\'\"]?"
)
SENSITIVE_VAR_ASSIGN_RE = re.compile(
    r"(?i)\b\w*(?:key|token|secret|password|passwd|pwd)\w*\s*[:=]\s*"
    r"[\'\"]?([A-Za-z0-9+/_\-]{32,})[\'\"]?"
)

ENTROPY_THRESHOLD = 3.0


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of `value`, in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def is_high_entropy(value: str, threshold: float = ENTROPY_THRESHOLD) -> bool:
    """Heuristic check: does this value look random enough to be a secret?

    This filters out low-entropy strings like "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    or "12345678901234567890123456789012" that happen to be long but are
    obviously not real random secrets.
    """
    return shannon_entropy(value) >= threshold


def mask(value: str) -> str:
    """Mask a secret value, keeping only the first/last 4 characters visible."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


@dataclass
class Finding:
    rule_name: str
    line_number: int
    matched_value: str
    line_text: str


def _spans_overlap(a: "tuple[int, int]", b: "tuple[int, int]") -> bool:
    return not (a[1] <= b[0] or a[0] >= b[1])


def scan_line(line: str, line_number: int) -> "list[Finding]":
    """Scan a single line of text and return any findings, in rule priority order.

    Rules are checked in a fixed priority order (private key header, AWS
    access key, generic API key, then generic high-entropy sensitive
    assignment) and a span already claimed by an earlier rule is not
    reported again by a later, broader rule.
    """
    findings: "list[Finding]" = []
    claimed: "list[tuple[int, int]]" = []

    def claim(span: "tuple[int, int]") -> bool:
        if any(_spans_overlap(span, existing) for existing in claimed):
            return False
        claimed.append(span)
        return True

    for match in PRIVATE_KEY_RE.finditer(line):
        span = match.span()
        if claim(span):
            findings.append(Finding("Private Key Header", line_number, match.group(0), line))

    for match in AWS_ACCESS_KEY_RE.finditer(line):
        span = match.span(1)
        if claim(span):
            findings.append(Finding("AWS Access Key", line_number, match.group(1), line))

    for match in GENERIC_API_KEY_RE.finditer(line):
        span = match.span(1)
        if claim(span):
            findings.append(Finding("Generic API Key", line_number, match.group(1), line))

    for match in SENSITIVE_VAR_ASSIGN_RE.finditer(line):
        span = match.span(1)
        value = match.group(1)
        if any(_spans_overlap(span, existing) for existing in claimed):
            continue
        if is_high_entropy(value):
            claim(span)
            findings.append(Finding("High-Entropy Secret Assignment", line_number, value, line))

    return findings


def scan_text(text: str) -> "list[Finding]":
    """Scan multi-line text and return all findings across all lines."""
    findings: "list[Finding]" = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(line, line_number))
    return findings
