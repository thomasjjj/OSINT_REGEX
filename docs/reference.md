# API Reference

This package is intentionally small. The public API is built around module-level helpers, a dynamic dispatcher, and a stable scan function.

## Import Style

Use the package directly:

```python
import osint_regex as osreg
```

The package is stdlib-only and expects decoded `str` input.

`phone` is the broad phone helper. `phone_e164` is the stricter E.164-style helper, and `tel` remains as a compatibility alias for it.

The repository homepage is https://github.com/thomasjjj/OSINT_REGEX.

## Canonical Helpers

Each canonical helper returns a list of matches for one category.

| Canonical helper | Legacy aliases | Return type | Notes |
| --- | --- | --- | --- |
| `email(text)` | `emails`, `find_emails` | `list[str]` | Email addresses are returned as full strings. |
| `website(text)` | `url`, `urls`, `websites`, `find_url`, `find_urls`, `find_websites` | `list[str]` | Matches common `http`, `https`, and `www.` forms. |
| `phone(text)` | `phone_number`, `phones`, `phone_numbers`, `find_phone_number`, `find_phones`, `find_phone_numbers` | `list[str]` | Heuristic phone matching, not full telephony validation. |
| `twitter_handle(text)` | `twitter_handles`, `find_twitter_handles` | `list[str]` | Returns the handle without the leading `@`. |
| `domain(text)` | `domains`, `hostname`, `hostnames`, `find_domain`, `find_domains`, `find_hostname`, `find_hostnames` | `list[str]` | Bare FQDN-style hostnames. |
| `ipv4(text)` | `ipv4_address`, `ipv4_addresses`, `find_ipv4`, `find_ipv4_address`, `find_ipv4_addresses` | `list[str]` | IPv4 addresses validated with `ipaddress`. |
| `ipv6(text)` | `ipv6_address`, `ipv6_addresses`, `find_ipv6`, `find_ipv6_address`, `find_ipv6_addresses` | `list[str]` | IPv6 addresses validated with `ipaddress`. |
| `cidr(text)` | `cidr_block`, `cidr_blocks`, `find_cidr`, `find_cidr_block`, `find_cidr_blocks` | `list[str]` | IP network prefixes validated with `ipaddress`. |
| `uuid(text)` | `uuids`, `find_uuid`, `find_uuids` | `list[str]` | Canonical UUID strings normalized with `uuid.UUID`. |
| `phone_e164(text)` | `tel`, `phone_e164s`, `find_tel`, `find_phone_e164`, `find_phone_e164s` | `list[str]` | Strict-ish E.164 phone numbers returned as `+digits`. |
| `btc_wallet(text)` | `btc_wallets`, `find_btc_wallets` | `list[str]` | Returns the full Bitcoin address. |
| `eth_wallet(text)` | `eth_wallets`, `find_eth_wallets` | `list[str]` | Full Ethereum address. |
| `monero_wallet(text)` | `monero_wallets`, `find_monero_wallets` | `list[str]` | Full Monero address. |
| `dash_wallet(text)` | `dash_wallets`, `find_dash_wallets` | `list[str]` | Full Dash address. |
| `cardano_wallet(text)` | `cardano_payment_address`, `cardano_wallets`, `find_cardano_wallets`, `find_cardano_payment_address` | `list[str]` | Full Cardano payment address. |
| `cardano_stake_address(text)` | `cardano_stake_addresses`, `find_cardano_stake_address`, `find_cardano_stake_addresses` | `list[str]` | Cardano stake or reward addresses. |
| `doge_wallet(text)` | `doge_wallets`, `find_doge_wallets` | `list[str]` | Full Dogecoin address. |
| `litecoin_wallet(text)` | `litecoin_wallets`, `find_litecoin_wallets` | `list[str]` | Full Litecoin address. |
| `ripple_wallet(text)` | `ripple_wallets`, `find_ripple_wallets` | `list[str]` | Full Ripple address. |
| `stellar_wallet(text)` | `stellar_wallets`, `find_stellar_wallets` | `list[str]` | Full Stellar address. |
| `transaction_hash(text)` | `transaction_hashes`, `find_transaction_hashes` | `list[str]` | 64-character hex hashes. |
| `onion_address(text)` | `onion`, `onions`, `onion_addresses`, `find_onion`, `find_onions`, `find_onion_address`, `find_onion_addresses` | `list[str]` | Tor v3 `.onion` addresses. |
| `bitcoin_cash_wallet(text)` | `bch_wallet`, `bch_wallets`, `find_bch_wallet`, `find_bch_wallets` | `list[str]` | CashAddr Bitcoin Cash addresses. |
| `tron_wallet(text)` | `tron_address`, `tron_addresses`, `tron_wallets`, `find_tron_address`, `find_tron_addresses`, `find_tron_wallets` | `list[str]` | Full TRON Base58Check addresses. |
| `solana_wallet(text)` | `solana_address`, `solana_addresses`, `solana_wallets`, `find_solana_address`, `find_solana_addresses`, `find_solana_wallets` | `list[str]` | Solana account addresses validated as Base58. |
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
# {'email': [...], 'phone': [...], 'latlon': [...], ...}
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
- The narrower helpers are regex-based format matches. They do not run checksum validation or interpret network-specific metadata.
- Some newer helpers do local validation after regex prefiltering, such as `ipv4`, `ipv6`, `cidr`, `uuid`, `phone_e164`, `bitcoin_cash_wallet`, `tron_wallet`, and `solana_wallet`.

## Extending the Package

The extractor registry lives in `osint_regex/__init__.py`.

To add a new category:

1. Add a compiled regex pattern.
2. Add an `ExtractorSpec` entry to `_SPECS`.
3. Give it canonical and legacy aliases if needed.
4. Add tests covering the canonical helper, `find`, and `scan`.

The module automatically exposes helpers for each canonical name and alias.
