# AGENTS.md

## Project

`osint_regex` is a stdlib-only Python package for extracting OSINT-style entities from text with regular expressions.

The public API is package-first:

- `import osint_regex as osreg`
- `osreg.email(text)`, `osreg.phone(text)`, `osreg.btc_wallet(text)`, and the other canonical helpers
- `osreg.find(text, kind)` for dynamic lookup
- `osreg.scan(text)` for a stable category-to-matches mapping

The repository is intentionally small and centered on:

- `osint_regex/__init__.py` for the public API and extractor registry
- `tests/` for behavior coverage
- `README.md` for usage and project overview

## Working Rules

- Keep changes ASCII unless an existing file already requires other characters.
- All file changes must either be added to git and committed or added to `.gitignore`.
- Do not leave generated files, cache directories, or local tooling artifacts unaccounted for in the tree.
- Prefer small, direct changes that preserve the package-first API.

## Notes

- The legacy single-file `OSINT_REGEX.py` entry point has been removed.
- Generated packaging metadata such as `*.egg-info/` should stay ignored rather than committed.
