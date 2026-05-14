import pytest

import osint_regex as osreg


def test_import_smoke_and_canonical_helpers():
    text = "Contact info@example.com or call +1 (555) 123-4567."

    assert osreg.email(text) == ["info@example.com"]
    assert osreg.phone(text) == ["+1 (555) 123-4567"]
    assert osreg.find(text, "phone") == ["+1 (555) 123-4567"]


def test_legacy_aliases_still_work():
    text = "Visit https://www.example.com and email admin@example.com"

    assert osreg.find_emails(text) == ["admin@example.com"]
    assert osreg.find_websites(text) == ["https://www.example.com"]
    assert osreg.OSINTRegex().find_emails(text) == ["admin@example.com"]


def test_btc_wallet_returns_full_address():
    address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"

    assert osreg.btc_wallet(address) == [address]
    assert osreg.find(address, "find_btc_wallets") == [address]


def test_price_and_latlon_helpers():
    text = "The price is USD 10.00 and 10 USD. Coordinates: 48.8584, 2.2945."

    assert osreg.price(text) == ["USD 10.00", "10 USD"]
    assert osreg.latlon(text) == [("48.8584", "2.2945")]


def test_scan_returns_stable_mapping_and_unknown_kind():
    text = "Email info@example.com and phone +1 (555) 123-4567."
    result = osreg.scan(text)

    assert list(result) == [
        "email",
        "website",
        "phone",
        "twitter_handle",
        "btc_wallet",
        "eth_wallet",
        "monero_wallet",
        "dash_wallet",
        "cardano_wallet",
        "doge_wallet",
        "litecoin_wallet",
        "ripple_wallet",
        "stellar_wallet",
        "transaction_hash",
        "price",
        "latlon",
        "long_string",
    ]
    assert result["email"] == ["info@example.com"]
    assert result["phone"] == ["+1 (555) 123-4567"]
    assert result["price"] == []

    with pytest.raises(KeyError):
        osreg.find(text, "not-a-kind")
