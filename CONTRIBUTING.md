# Contributing

Thanks for considering a contribution — this project is MIT licensed, so bug
reports, fixes, and small features are welcome.

## Setup

```bash
git clone https://github.com/sidcore-dev/gitleaks-lite-cli.git
cd gitleaks-lite-cli
pip install -e . pytest
```

## Running tests

```bash
pytest
```

## Making a change

1. Fork the repo and create a branch off `main`.
2. Keep the change focused — this is a small, single-purpose tool, so a PR
   that adds one thing is much easier to review than one that adds several.
3. Add or update tests under `tests/` for any behavior change.
4. Open a PR describing what changed and why.

## Reporting a bug

Open an issue with the command you ran, what you expected, and what
happened instead. A minimal reproduction (a sample input file, if relevant)
speeds things up a lot.
