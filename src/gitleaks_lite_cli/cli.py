"""Command-line entry point for gitleaks-lite-cli."""
from __future__ import annotations

import argparse
import os
import sys
from typing import TextIO

from .core import mask, scan_text

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gitleaks-lite-cli",
        description="Heuristically scan files or a directory for strings that look like "
        "common secrets (regex + entropy checks only; no network calls).",
    )
    parser.add_argument("paths", nargs="+", help="Files and/or directories to scan")
    return parser


def collect_files(path: str) -> "list[str]":
    """Return all regular files under `path` (recursively, if it's a directory)."""
    if os.path.isfile(path):
        return [path]
    if not os.path.isdir(path):
        return []

    files: "list[str]" = []
    for root, dirs, filenames in os.walk(path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in filenames:
            files.append(os.path.join(root, filename))
    return files


def main(argv: "list[str] | None" = None, out: "TextIO | None" = None, err: "TextIO | None" = None) -> int:
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr

    parser = build_parser()
    args = parser.parse_args(argv)

    files: "list[str]" = []
    for path in args.paths:
        if os.path.isfile(path) or os.path.isdir(path):
            files.extend(collect_files(path))
        else:
            print(f"gitleaks-lite-cli: warning: {path}: no such file or directory", file=err)

    total_findings = 0
    scanned = 0
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"gitleaks-lite-cli: warning: could not read {path}: {exc}", file=err)
            continue

        scanned += 1
        for finding in scan_text(text):
            print(f"{path}:{finding.line_number}: {finding.rule_name}: {mask(finding.matched_value)}", file=out)
            total_findings += 1

    if total_findings:
        print(
            f"gitleaks-lite-cli: found {total_findings} potential secret(s) across {scanned} file(s) scanned",
            file=out,
        )
        return 1

    print(f"gitleaks-lite-cli: no potential secrets found ({scanned} file(s) scanned)", file=out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
