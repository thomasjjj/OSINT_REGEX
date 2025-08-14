import os, sys; sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import pytest
from OSINT_REGEX import OSINTRegex


@pytest.fixture
def osint():
    return OSINTRegex()


def test_find_emails(osint):
    valid = "Contact us at info@example.com"
    invalid = "Contact at info@example without domain"
    assert osint.find_emails(valid) == ["info@example.com"]
    assert osint.find_emails(invalid) == []


def test_find_websites(osint):
    valid = "Visit https://www.example.com for info"
    invalid = "Visit example without domain"
    assert osint.find_websites(valid) == ["https://www.example.com"]
    assert osint.find_websites(invalid) == []


def test_find_twitter_handles(osint):
    valid = "@OpenAI"
    invalid = "@thishandleistoolong"
    assert osint.find_twitter_handles(valid) == ["OpenAI"]
    assert osint.find_twitter_handles(invalid) == []


def test_find_btc_wallets(osint):
    valid = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    invalid = "4BoatSLRHtKNngkdXEeobR76b53LETtpyT"
    assert osint.find_btc_wallets(valid) == ["1"]
    assert osint.find_btc_wallets(invalid) == []


def test_find_eth_wallets(osint):
    valid = "0x" + "a" * 40
    invalid = "0x" + "g" * 40
    assert osint.find_eth_wallets(valid) == [valid]
    assert osint.find_eth_wallets(invalid) == []


def test_find_monero_wallets(osint):
    valid = "4A" + "1" * 93
    invalid = "5A" + "1" * 93
    assert osint.find_monero_wallets(valid) == [valid]
    assert osint.find_monero_wallets(invalid) == []


def test_find_dash_wallets(osint):
    valid = "X" + "1" * 33
    invalid = "Y" + "1" * 33
    assert osint.find_dash_wallets(valid) == [valid]
    assert osint.find_dash_wallets(invalid) == []


def test_find_cardano_wallets(osint):
    valid = "addr1abc123"
    invalid = "addrabc123"
    assert osint.find_cardano_wallets(valid) == [valid]
    assert osint.find_cardano_wallets(invalid) == []


def test_find_doge_wallets(osint):
    valid = "D" + "A" * 33
    invalid = "E" + "A" * 33
    assert osint.find_doge_wallets(valid) == [valid]
    assert osint.find_doge_wallets(invalid) == []


def test_find_litecoin_wallets(osint):
    valid = "L" + "1" * 26
    invalid = "O" + "1" * 26
    assert osint.find_litecoin_wallets(valid) == [valid]
    assert osint.find_litecoin_wallets(invalid) == []


def test_find_ripple_wallets(osint):
    valid = "r" + "A" * 33
    invalid = "s" + "A" * 33
    assert osint.find_ripple_wallets(valid) == [valid]
    assert osint.find_ripple_wallets(invalid) == []


def test_find_stellar_wallets(osint):
    valid = "G" + "A" * 40
    invalid = "H" + "A" * 40
    assert osint.find_stellar_wallets(valid) == [valid]
    assert osint.find_stellar_wallets(invalid) == []


def test_find_transaction_hashes(osint):
    valid = "a" * 64
    invalid = "g" * 64
    assert osint.find_transaction_hashes(valid) == [valid]
    assert osint.find_transaction_hashes(invalid) == []


def test_find_prices(osint):
    valid = "The price is USD 10.00 and 10 USD"
    invalid = "The price is 10.00"
    assert osint.find_prices(valid) == ["USD 10.00", "10 USD"]
    assert osint.find_prices(invalid) == []


def test_find_latlon(osint):
    valid = "48.8584, 2.2945"
    invalid = "91.0000, 181.0000"
    assert osint.find_latlon(valid) == [("48.8584", "2.2945")]
    assert osint.find_latlon(invalid) == []


def test_find_long_strings(osint):
    long_str = "a" * 20
    short_str = "a" * 19
    assert osint.find_long_strings(long_str) == [long_str]
    assert osint.find_long_strings(short_str) == []
