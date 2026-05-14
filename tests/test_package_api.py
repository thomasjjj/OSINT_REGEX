import re
from pathlib import Path

import pytest

import osint_regex as osreg


CANONICAL_CASES = [
    ("email", "Reach info@example.com.", ["info@example.com"]),
    (
        "website",
        "Visit https://www.example.com/about.",
        ["https://www.example.com/about"],
    ),
    ("phone", "Call +1 (555) 123-4567.", ["+1 (555) 123-4567"]),
    ("twitter_handle", "Follow @OpenAI.", ["OpenAI"]),
    (
        "btc_wallet",
        "BTC 1BoatSLRHtKNngkdXEeobR76b53LETtpyT.",
        ["1BoatSLRHtKNngkdXEeobR76b53LETtpyT"],
    ),
    ("eth_wallet", f"ETH 0x{'a' * 40}.", [f"0x{'a' * 40}"]),
    ("monero_wallet", f"Monero 4A{'1' * 93}.", [f"4A{'1' * 93}"]),
    ("dash_wallet", f"Dash X{'1' * 33}.", [f"X{'1' * 33}"]),
    ("cardano_wallet", "Cardano addr1abc123.", ["addr1abc123"]),
    ("doge_wallet", f"Doge D{'A' * 33}.", [f"D{'A' * 33}"]),
    ("litecoin_wallet", f"Litecoin L{'1' * 26}.", [f"L{'1' * 26}"]),
    ("ripple_wallet", f"Ripple r{'A' * 33}.", [f"r{'A' * 33}"]),
    ("stellar_wallet", f"Stellar G{'A' * 40}.", [f"G{'A' * 40}"]),
    ("transaction_hash", f"Hash {'a' * 64}.", ["a" * 64]),
    (
        "price",
        "Prices: USD 10.00, 10 USD, and €12.50.",
        ["USD 10.00", "10 USD", "€12.50"],
    ),
    ("latlon", "Coordinates: 48.8584, 2.2945.", [("48.8584", "2.2945")]),
    ("long_string", "OpaqueValue_1234567890", ["OpaqueValue_1234567890"]),
]

NEGATIVE_CASES = [
    ("email", "Reach info@example without a domain."),
    ("website", "Visit example without a domain."),
    ("phone", "Call 1234 for help."),
    ("twitter_handle", "No social handle here."),
    ("btc_wallet", "BTC 4BoatSLRHtKNngkdXEeobR76b53LETtpyT."),
    ("eth_wallet", f"ETH 0x{'g' * 40}."),
    ("monero_wallet", f"Monero 5A{'1' * 93}."),
    ("dash_wallet", f"Dash Y{'1' * 33}."),
    ("cardano_wallet", "Cardano addrabc123."),
    ("doge_wallet", f"Doge E{'A' * 33}."),
    ("litecoin_wallet", f"Litecoin O{'1' * 26}."),
    ("ripple_wallet", f"Ripple s{'A' * 33}."),
    ("stellar_wallet", f"Stellar H{'A' * 40}."),
    ("transaction_hash", f"Hash {'g' * 64}."),
    ("price", "The amount is 10.00."),
    ("latlon", "Coordinates: 91.0000, 181.0000."),
    ("long_string", "a" * 19),
]

ALIAS_CASES = [
    ("email", "find_emails"),
    ("website", "find_websites"),
    ("phone", "find_phone_numbers"),
    ("btc_wallet", "find_btc_wallets"),
    ("price", "find_prices"),
    ("latlon", "find_latlon"),
    ("long_string", "find_long_strings"),
]

SAMPLES = {kind: text for kind, text, _ in CANONICAL_CASES}
CANONICAL_KINDS = [kind for kind, _, _ in CANONICAL_CASES]
COMBINED_TEXT = "\n".join(text for _, text, _ in CANONICAL_CASES)


@pytest.mark.parametrize("kind,text,expected", CANONICAL_CASES)
def test_canonical_helpers_and_find(kind, text, expected):
    helper = getattr(osreg, kind)

    assert helper(text) == expected
    assert osreg.find(text, kind) == expected


@pytest.mark.parametrize("kind,text", NEGATIVE_CASES)
def test_helpers_return_empty_lists_for_non_matches(kind, text):
    helper = getattr(osreg, kind)

    assert helper(text) == []
    assert osreg.find(text, kind) == []


@pytest.mark.parametrize("kind,alias", ALIAS_CASES)
def test_find_accepts_aliases(kind, alias):
    text = SAMPLES[kind]

    assert osreg.find(text, alias) == getattr(osreg, kind)(text)


def test_find_normalizes_kind_names():
    text = SAMPLES["phone"]

    assert osreg.find(text, "  PHONE  ") == osreg.phone(text)


def test_scan_returns_stable_mapping_and_matches_helpers():
    result = osreg.scan(COMBINED_TEXT)

    assert list(result) == CANONICAL_KINDS
    assert result == {
        kind: getattr(osreg, kind)(COMBINED_TEXT) for kind in CANONICAL_KINDS
    }


def test_scan_empty_input_returns_all_categories():
    result = osreg.scan("")

    assert list(result) == CANONICAL_KINDS
    assert all(values == [] for values in result.values())


def test_public_exports_and_version_match_project_metadata():
    exported = set(osreg.__all__)
    expected_exports = {
        "OSINTRegex",
        "__version__",
        "find",
        "scan",
        "email",
        "website",
        "phone",
        "btc_wallet",
        "latlon",
    }

    assert expected_exports.issubset(exported)
    assert len(osreg.__all__) == len(exported)
    assert osreg.__version__ == "0.2.1"

    pyproject_text = Path("pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject_text, re.MULTILINE)
    assert match is not None
    assert match.group(1) == osreg.__version__


def test_osintregex_wrapper_matches_module_helpers():
    wrapper = osreg.OSINTRegex()
    text = SAMPLES["email"] + " " + SAMPLES["phone"] + " " + SAMPLES["btc_wallet"]

    assert wrapper.email(text) == osreg.email(text)
    assert wrapper.find(text, "email") == osreg.find(text, "email")
    assert wrapper.scan(text) == osreg.scan(text)
