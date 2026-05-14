# API Reference

This package is intentionally small. The public API is built around module-level helpers, a dynamic dispatcher, and a stable scan function.

## Import Style

Use the package directly:

```python
import osint_regex as osreg
```

The package is stdlib-only and expects decoded `str` input.

## Canonical Helpers

Each canonical helper returns a list of matches for one category.

| Canonical helper | Legacy aliases | Return type | Notes |
| --- | --- | --- | --- |
| `email(text)` | `emails`, `find_emails` | `list[str]` | Email addresses are returned as full strings. |
| `website(text)` | `websites`, `find_websites` | `list[str]` | Matches common `http`, `https`, and `www.` forms. |
| `phone(text)` | `phone_number`, `phones`, `phone_numbers`, `find_phone_number`, `find_phones`, `find_phone_numbers` | `list[str]` | Heuristic phone matching, not full telephony validation. |
| `twitter_handle(text)` | `twitter_handles`, `find_twitter_handles` | `list[str]` | Returns the handle without the leading `@`. |
| `btc_wallet(text)` | `btc_wallets`, `find_btc_wallets` | `list[str]` | Returns the full Bitcoin address. |
| `eth_wallet(text)` | `eth_wallets`, `find_eth_wallets` | `list[str]` | Full Ethereum address. |
| `monero_wallet(text)` | `monero_wallets`, `find_monero_wallets` | `list[str]` | Full Monero address. |
| `dash_wallet(text)` | `dash_wallets`, `find_dash_wallets` | `list[str]` | Full Dash address. |
| `cardano_wallet(text)` | `cardano_wallets`, `find_cardano_wallets` | `list[str]` | Full Cardano address. |
| `doge_wallet(text)` | `doge_wallets`, `find_doge_wallets` | `list[str]` | Full Dogecoin address. |
| `litecoin_wallet(text)` | `litecoin_wallets`, `find_litecoin_wallets` | `list[str]` | Full Litecoin address. |
| `ripple_wallet(text)` | `ripple_wallets`, `find_ripple_wallets` | `list[str]` | Full Ripple address. |
| `stellar_wallet(text)` | `stellar_wallets`, `find_stellar_wallets` | `list[str]` | Full Stellar address. |
| `transaction_hash(text)` | `transaction_hashes`, `find_transaction_hashes` | `list[str]` | 64-character hex hashes. |
| `price(text)` | `prices`, `find_prices` | `list[str]` | Currency-prefixed or currency-suffixed values. |
| `latlon(text)` | `latlon_pairs`, `find_latlon` | `list[tuple[str, str]]` | Returns `(latitude, longitude)` tuples. |
| `long_string(text)` | `long_strings`, `find_long_strings` | `list[str]` | Long alphanumeric strings of 20 or more characters. |

## Dynamic Lookup

`find(text, kind)` resolves a canonical name or any documented alias.

Examples:

```python
osreg.find(text, "phone")
osreg.find(text, "find_btc_wallets")
osreg.find(text, "latlon")
```

If `kind` is unknown, `find` raises `KeyError` with the list of valid canonical kinds.

## Full Scan

`scan(text)` returns a dictionary keyed by canonical category name.

Important properties:

- The order is stable because the registry is defined in a fixed sequence.
- Every canonical category is always present.
- Categories with no matches are included as empty lists.

Example:

```python
result = osreg.scan(text)
print(result["email"])
print(result["phone"])
print(result["latlon"])
```

## Compatibility Wrapper

`OSINTRegex` is kept for older code that instantiates a class instead of using module-level helpers.

Prefer this style for new code:

```python
import osint_regex as osreg
osreg.email(text)
```

Legacy style still works:

```python
from osint_regex import OSINTRegex
osint = OSINTRegex()
osint.find_emails(text)
```

## Input Expectations

The package does not auto-detect encodings.

- Decode `bytes` into `str` before calling the API.
- UTF-8, Windows-1252, Latin-1, and similar encodings all work once decoded.
- The regex patterns are mostly ASCII-oriented, so odd punctuation and locale-specific formatting can affect match quality.

## Matching Notes

- Results come from `re.finditer`, so capture groups do not leak into outputs.
- Trailing punctuation such as commas and periods is trimmed from full-string matches.
- Phone numbers are intentionally heuristic and accept common display formats rather than enforcing a single global numbering standard.
- Latitude/longitude extraction is also heuristic, so standalone coordinate text works best; numeric text that looks coordinate-like can produce false positives.
- Latitude/longitude values are returned as strings so callers can decide how and when to convert them.

## Extending the Package

The extractor registry lives in `osint_regex/__init__.py`.

To add a new category:

1. Add a compiled regex pattern.
2. Add an `ExtractorSpec` entry to `_SPECS`.
3. Give it canonical and legacy aliases if needed.
4. Add tests covering the canonical helper, `find`, and `scan`.

The module automatically exposes helpers for each canonical name and alias.
