# gitleaks-lite-cli

[![CI](https://github.com/sidcore-dev/gitleaks-lite-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/sidcore-dev/gitleaks-lite-cli/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/sidcore-dev/gitleaks-lite-cli)](https://github.com/sidcore-dev/gitleaks-lite-cli/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


A small, dependency-free heuristic secret scanner. It walks a file or
directory looking for text patterns that commonly indicate an accidentally
committed credential — AWS access keys, private key headers, generic
`api_key`-style assignments, and high-entropy strings assigned to
suspiciously-named variables — and reports where it found them, with the
matched value masked.

## Important: this is a heuristic, not a guarantee

**Read this before relying on it.** This tool only does regex
pattern-matching plus a basic Shannon-entropy check on candidate values.
It:

- makes **no network calls** and verifies nothing against any real service
  (it cannot tell a live AWS key from a fake or revoked one);
- **will produce false positives** — a long random-looking test fixture, a
  hash, or a UUID assigned to a variable named `token` can trip it;
- **will produce false negatives** — a real secret that doesn't match one
  of its patterns (an unusual format, split across lines, base64-wrapped
  another way, etc.) will sail right through undetected.

It is meant as a lightweight pre-commit / CI sanity check to catch your
**own** obvious mistakes before they land in a repo — not as a security
audit tool, not as a way to search for other people's leaked secrets, and
not as a substitute for a real secret-scanning product or for actually
rotating anything it finds.

## Why

Most "did I just commit a secret" checks require signing up for a hosted
scanner or installing a large Go binary. This is a few hundred lines of
Python stdlib that does the common 80% case — catching the AWS key or API
token you pasted into a config file by mistake — with zero setup.

## Install

```bash
pip install .
```

This installs a `gitleaks-lite-cli` command on your PATH.

## Usage

```bash
gitleaks-lite-cli config.py             # scan a single file
gitleaks-lite-cli .                     # scan a directory recursively
gitleaks-lite-cli src/ tests/ app.py    # scan multiple paths at once
```

Example output:

```
$ gitleaks-lite-cli .
./config.py:3: AWS Access Key: AKIA************MNOP
./deploy.sh:12: Private Key Header: ----************----
gitleaks-lite-cli: found 2 potential secret(s) across 14 file(s) scanned
```

Clean run:

```
$ gitleaks-lite-cli .
gitleaks-lite-cli: no potential secrets found (14 file(s) scanned)
```

Matched values are never printed in full — only the first and last 4
characters are shown, with everything in between replaced by `*`.

### What it looks for

| Rule                          | Roughly matches                                              |
|--------------------------------|----------------------------------------------------------------|
| AWS Access Key                 | `AKIA`/`ASIA` followed by 16 uppercase letters/digits          |
| Private Key Header             | `-----BEGIN ... PRIVATE KEY-----` (RSA, EC, OPENSSH, plain, ...) |
| Generic API Key                | an `api_key`/`apikey`/`api-key` assignment with a 16-64 char value |
| High-Entropy Secret Assignment | a variable named like `*key*`, `*token*`, `*secret*`, `*password*` assigned a 32+ char value that looks random (Shannon entropy check), rather than e.g. a repeated character |

`.git`, `node_modules`, `.venv`/`venv`, `__pycache__`, `.mypy_cache`, and
`.pytest_cache` directories are skipped automatically when scanning a
directory.

### Exit codes

| Code | Meaning                              |
|------|----------------------------------------|
| 0    | No potential secrets found              |
| 1    | At least one potential secret was found |

## Development

```bash
pip install -e .
python -m unittest discover -s tests -v
```

## License

All rights reserved. This code is public for viewing and reference only —
no license is granted to use, copy, modify, or redistribute it. See
[LICENSE](LICENSE) for details.
