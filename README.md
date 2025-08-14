# OSINT Regex

A curated collection of regular expressions for extracting common OSINT artifacts from text.

## Installation

This project has no third‑party dependencies beyond the Python standard library.

```bash
git clone https://github.com/yourname/OSINT_REGEX.git
cd OSINT_REGEX
python3 -m venv .venv
source .venv/bin/activate
# Optionally run the example script
python OSINT_REGEX.py
```

## API Usage

```python
from OSINT_REGEX import OSINTRegex

text = "Contact us at info@example.com or visit https://example.com"
osint = OSINTRegex()
print(osint.find_emails(text))
```

## Pattern Catalog

- **Emails** (`find_emails`) – `r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'`
- **Websites** (`find_websites`) – `r'\b(?:https?://)?(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?\b'`
- **Twitter handles** (`find_twitter_handles`) – `r'@([A-Za-z0-9_]{1,15})\b'`
- **Bitcoin wallets** (`find_btc_wallets`) – `r'\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'`
- **Ethereum wallets** (`find_eth_wallets`) – `r'\b0x[a-fA-F0-9]{40}\b'`
- **Monero wallets** (`find_monero_wallets`) – `r'\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b'`
- **Dash wallets** (`find_dash_wallets`) – `r'\bX[1-9A-HJ-NP-Za-km-z]{33}\b'`
- **Cardano wallets** (`find_cardano_wallets`) – `r'\baddr1[a-z0-9]+\b'`
- **Dogecoin wallets** (`find_doge_wallets`) – `r'\bD[a-zA-Z0-9_.-]{33}\b'`
- **Litecoin wallets** (`find_litecoin_wallets`) – `r'\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b'`
- **Ripple wallets** (`find_ripple_wallets`) – `r'\br[0-9a-zA-Z]{33}\b'`
- **Stellar wallets** (`find_stellar_wallets`) – `r'\bG[0-9A-Z]{40,60}\b'`
- **Transaction hashes** (`find_transaction_hashes`) – `r'\b[a-fA-F0-9]{64}\b'`
- **Prices** (`find_prices`) – `r'((USD|EUR|€|\$)\s?(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2}))|(\d{1,3}(?:[.,]\d{3})*(?:[.,]\d{2})?)\s?(USD|EUR|€|\$))'`
- **Latitude/Longitude pairs** (`find_latlon`) – `r'(?<!\d)([-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\s*,\s*([-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?))(?!\d)'`
- **Long strings** (`find_long_strings`) – `r'\b[a-zA-Z0-9_.-]{20,}\b'`

## Contributing

1. Fork the repository and create a new branch for your feature.
2. Add your regex as a new `find_*` method in `OSINT_REGEX.py` with a clear docstring.
3. Update this README's pattern catalog with the new method and pattern.
4. Add tests in a `tests/` directory and run them with `pytest`.
5. Ensure `python OSINT_REGEX.py` runs without errors.
6. Submit a pull request.

## Documentation

As the library grows, consider generating API documentation with [MkDocs](https://www.mkdocs.org/) or [Sphinx](https://www.sphinx-doc.org/) and hosting it on GitHub Pages or Read the Docs.

Use for Good. Use with care.

