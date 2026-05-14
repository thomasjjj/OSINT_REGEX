# osint_regex

Stdlib-only regular expression helpers for extracting common OSINT artifacts from text.

## What it does

`osint_regex` is a registry-driven package for finding:

- emails
- websites
- phone numbers
- social handles
- wallet addresses
- transaction hashes
- prices
- latitude/longitude pairs
- long opaque strings

The preferred import style is:

```python
import osint_regex as osreg
```

## Quick Start

```bash
python -m pip install -e .
```

```python
import osint_regex as osreg

text = """
Contact info@example.com, call +1 (555) 123-4567,
visit https://www.example.com, and send 1BoatSLRHtKNngkdXEeobR76b53LETtpyT.
"""

print(osreg.email(text))
print(osreg.phone(text))
print(osreg.find(text, "btc_wallet"))
print(osreg.scan(text))
```

## Core API

Canonical helpers:

- `email(text)`
- `website(text)`
- `phone(text)`
- `twitter_handle(text)`
- `btc_wallet(text)`
- `eth_wallet(text)`
- `monero_wallet(text)`
- `dash_wallet(text)`
- `cardano_wallet(text)`
- `doge_wallet(text)`
- `litecoin_wallet(text)`
- `ripple_wallet(text)`
- `stellar_wallet(text)`
- `transaction_hash(text)`
- `price(text)`
- `latlon(text)`
- `long_string(text)`

Dynamic lookup:

- `find(text, kind)`
- `scan(text)`

Compatibility:

- Legacy `find_*` aliases remain available.
- `OSINTRegex` is still provided for older call sites.

## Behavior

- `find` accepts canonical kinds such as `"phone"` and legacy aliases such as `"find_phone_numbers"`.
- `scan` returns a stable dictionary with every canonical category included.
- Match lists are normalized from `re.finditer`, so capture groups do not leak into results.
- `phone` is heuristic rather than a full international numbering parser.
- `latlon` is also heuristic and works best on standalone coordinate text.
- The package expects decoded `str` input. Decode `bytes` before calling the API.

## Documentation

See the full reference in the repository: https://github.com/thomasjjj/OSINT_REGEX/blob/master/docs/reference.md

## Publishing

```bash
python -m pip install build twine
python -m build
python -m twine check dist/*
python -m twine upload dist/*
```

For a dry run, upload to TestPyPI first:

```bash
python -m twine upload --repository testpypi dist/*
```

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy osint_regex tests
python -m build
python -m pre_commit run --all-files
```
