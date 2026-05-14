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

The package targets Python 3.8+ and preserves a package-first import style.

## Working Rules

- Keep changes ASCII unless an existing file already requires other characters.
- All file changes must either be added to git and committed or added to `.gitignore`.
- Do not leave generated files, cache directories, or local tooling artifacts unaccounted for in the tree.
- Do not use destructive git commands such as `git reset --hard`, `git checkout --`, or history rewriting unless explicitly requested.
- Do not revert user or prior-agent changes unless they directly block the task and the user has approved it.
- Preserve the public API and update tests and docs whenever behavior changes.
- Prefer small, direct changes that preserve the package-first API.
- Keep the version number, packaging metadata, and release artifacts in sync.

## Required Validation

Any change that affects code, packaging, tests, docs, or release metadata should be validated with the full release gate:

1. `python -m pytest -q`
2. `python -m ruff check .`
3. `python -m ruff format --check .`
4. `python -m mypy osint_regex tests`
5. `python -m build`
6. `python -m twine check dist/*`
7. `python -m pre_commit run --all-files`

If a change touches the installed package or release metadata, also verify the built artifact imports correctly:

1. Install the wheel from `dist/`.
2. Run a quick smoke import such as `python -c "import osint_regex as osreg; print(osreg.__version__)"`.

If a validation step fails because of a tool-version mismatch, update the pinned tooling or workflow instead of weakening the check.

## Repo Hygiene

- Keep generated build outputs out of version control.
- Keep `dist/`, `build/`, `*.egg-info/`, cache directories, `.idea/`, and virtual environments ignored.
- If a new generated artifact appears during work, either add it to `.gitignore` or commit it intentionally if it is a required source artifact.
- Avoid checking in machine-specific files unless they are required for the project to function.

## Notes

- The legacy single-file `OSINT_REGEX.py` entry point has been removed.
- Generated packaging metadata such as `*.egg-info/` should stay ignored rather than committed.
- The release checklist is intentionally strict so the package stays publishable without extra cleanup.
- The project is MIT-licensed; keep `LICENSE` and packaging metadata aligned when making release changes.
