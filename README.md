# osint_regex

Stdlib-only regular expression helpers for extracting common OSINT artifacts from text.

## Install

```bash
python -m pip install -e .
```

## Use

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

## API

Canonical helpers are function-first:

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

Dynamic lookup is available through:

- `find(text, kind)`
- `scan(text)`

Legacy `find_*` names remain as thin aliases during the transition, so existing call sites can move over gradually.

`scan(text)` returns a stable dictionary keyed by canonical category name, with empty lists included for categories that do not match.

## Development

```bash
pytest
```
