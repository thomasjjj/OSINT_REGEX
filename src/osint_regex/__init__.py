"""OSINT regex patterns and helpers."""

from .patterns import OSINTRegex

_default = OSINTRegex()

find_emails = _default.find_emails
find_websites = _default.find_websites
find_twitter_handles = _default.find_twitter_handles
find_btc_wallets = _default.find_btc_wallets
find_eth_wallets = _default.find_eth_wallets
find_monero_wallets = _default.find_monero_wallets
find_dash_wallets = _default.find_dash_wallets
find_cardano_wallets = _default.find_cardano_wallets
find_doge_wallets = _default.find_doge_wallets
find_litecoin_wallets = _default.find_litecoin_wallets
find_ripple_wallets = _default.find_ripple_wallets
find_stellar_wallets = _default.find_stellar_wallets
find_transaction_hashes = _default.find_transaction_hashes
find_prices = _default.find_prices
find_latlon = _default.find_latlon
find_long_strings = _default.find_long_strings

__all__ = [
    "OSINTRegex",
    "find_emails",
    "find_websites",
    "find_twitter_handles",
    "find_btc_wallets",
    "find_eth_wallets",
    "find_monero_wallets",
    "find_dash_wallets",
    "find_cardano_wallets",
    "find_doge_wallets",
    "find_litecoin_wallets",
    "find_ripple_wallets",
    "find_stellar_wallets",
    "find_transaction_hashes",
    "find_prices",
    "find_latlon",
    "find_long_strings",
]
