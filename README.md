# osint_regex

Stdlib-only regular expression helpers for extracting common OSINT artifacts from text.

## What it does

`osint_regex` is a registry-driven package for finding common OSINT artifacts from text.

The extractors fall into two groups:

- Broad heuristic helpers that favor recall on messy text, such as `website`, `phone`, `price`, `latlon`, and `long_string`.
- Standardized or format-based helpers that target known syntaxes, such as `email`, `twitter_handle`, `domain`, `ipv4`, `ipv6`, `cidr`, `uuid`, `phone_e164`, the wallet/hash categories, `transaction_hash`, `onion_address`, and `solana_wallet`.

All helpers are regex-based. Heuristic helpers cast a wider net on noisy text. The narrower helpers are still pattern matchers, not checksum validators or protocol parsers.

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
visit https://www.example.com, mention @openai,
and send 1BoatSLRHtKNngkdXEeobR76b53LETtpyT.
"""

print(osreg.website(text))
print(osreg.email(text))
print(osreg.phone(text))
print(osreg.twitter_handle(text))
print(osreg.find(text, "btc_wallet"))
print(osreg.latlon("Coords 51.5074, -0.1278"))
print(osreg.scan(text))
```

## Core API

Canonical helpers are grouped by matching style:

Broad heuristic helpers:

- `website(text)`
- `phone(text)`
- `price(text)`
- `latlon(text)`
- `long_string(text)`

Format-based helpers:

- `email(text)`
- `twitter_handle(text)`
- `domain(text)`
- `ipv4(text)`
- `ipv6(text)`
- `cidr(text)`
- `uuid(text)`
- `phone_e164(text)`
- `btc_wallet(text)`
- `eth_wallet(text)`
- `monero_wallet(text)`
- `dash_wallet(text)`
- `cardano_wallet(text)`
- `cardano_stake_address(text)`
- `doge_wallet(text)`
- `litecoin_wallet(text)`
- `ripple_wallet(text)`
- `stellar_wallet(text)`
- `transaction_hash(text)`
- `onion_address(text)`
- `bitcoin_cash_wallet(text)`
- `tron_wallet(text)`
- `solana_wallet(text)`

Dynamic lookup:

- `find(text, kind)`
- `scan(text)`

Compatibility:

- Legacy plural aliases, compatibility aliases, and `find_*` aliases remain available for the original helpers, including forms such as `emails`, `phones`, `btc_wallets`, `url`, `hostname`, `bch_wallet`, `cardano_payment_address`, `tel`, and `find_phone_numbers`.
- `OSINTRegex` is still provided for older call sites.

## Behavior

- `find` accepts canonical kinds such as `"phone"` and legacy aliases such as `"find_phone_numbers"`.
- `scan` returns a stable dictionary with every canonical category included.
- Match lists are normalized from `re.finditer`, so capture groups do not leak into results.
- `phone` is the broad phone helper. `phone_e164` is the stricter E.164-style helper, and `tel` remains available as a compatibility alias for it.
- `url` is a compatibility alias for `website`, and `hostname` is a compatibility alias for `domain`.
- `website`, `phone`, `price`, `latlon`, and `long_string` are broad heuristic helpers. They are designed for useful recall on noisy text, not strict validation.
- `email`, `twitter_handle`, `domain`, `ipv4`, `ipv6`, `cidr`, `uuid`, `phone_e164`, `onion_address`, `bitcoin_cash_wallet`, `cardano_stake_address`, `tron_wallet`, `solana_wallet`, the wallet/hash extractors, and `transaction_hash` are narrower format helpers. Most still rely on regex patterns plus local validation and do not perform network calls.
- `latlon` works best on standalone coordinate text.
- The package expects decoded `str` input. Decode `bytes` before calling the API.

## Documentation

See the full reference in the repository: https://github.com/thomasjjj/OSINT_REGEX/blob/master/docs/reference.md


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
