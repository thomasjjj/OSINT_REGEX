import hashlib
import importlib.util
import ipaddress
import re
import sys
from pathlib import Path
import uuid as uuid_mod

import pytest


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: idx for idx, char in enumerate(_BASE58_ALPHABET)}


def _b58decode(value):
    total = 0
    for char in value:
        try:
            total = total * 58 + _BASE58_INDEX[char]
        except KeyError as exc:
            raise ValueError(f"Invalid base58 character: {char!r}") from exc
    raw = total.to_bytes((total.bit_length() + 7) // 8, "big") if total else b""
    pad = len(value) - len(value.lstrip("1"))
    return b"\x00" * pad + raw


def _b58check_decode(value):
    decoded = _b58decode(value)
    if len(decoded) < 4:
        raise ValueError("Base58Check payload is too short")
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("Invalid Base58Check checksum")
    return payload


def _validate_domain(value):
    candidate = value.rstrip(".")
    if len(candidate) > 253 or candidate.count(".") < 1:
        return False
    if re.fullmatch(r"\d+(?:\.\d+){3}", candidate):
        return False
    labels = candidate.split(".")
    if len(labels[-1]) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
        if not re.fullmatch(r"[A-Za-z0-9-]+", label):
            return False
    tld = labels[-1]
    return bool(
        re.fullmatch(r"[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{2,59}", tld, re.IGNORECASE)
    )


def _validate_ipv4(value):
    try:
        return isinstance(ipaddress.IPv4Address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def _validate_ipv6(value):
    candidate = value.split("%", 1)[0]
    try:
        return isinstance(ipaddress.IPv6Address(candidate), ipaddress.IPv6Address)
    except ValueError:
        return False


def _validate_cidr(value):
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _validate_uuid(value):
    try:
        return str(uuid_mod.UUID(value))
    except ValueError:
        return None


def _validate_phone_e164(value):
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 15:
        return None
    if digits[0] == "0":
        return None
    return f"+{digits}"


def _validate_onion_address(value):
    candidate = value.lower()
    if not candidate.endswith(".onion"):
        return False
    host = candidate[:-6]
    if len(host) != 56:
        return False
    return all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in host)


_CASHADDR_ALPHABET = set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
_CASHADDR_PREFIXES = {"bitcoincash", "bchtest", "bchreg"}


def _validate_bitcoin_cash_wallet(value):
    prefix, sep, payload = value.partition(":")
    if not sep:
        return False
    if prefix.lower() not in _CASHADDR_PREFIXES:
        return False
    payload = payload.lower()
    if len(payload) < 20:
        return False
    return all(char in _CASHADDR_ALPHABET for char in payload)


def _validate_tron(value):
    if not re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", value):
        return False
    try:
        payload = _b58check_decode(value)
    except ValueError:
        return False
    return len(payload) == 21 and payload.startswith(b"\x41")


def _validate_solana(value):
    try:
        decoded = _b58decode(value)
    except ValueError:
        return False
    return len(decoded) == 32


def _load_osint_regex():
    module_path = Path(__file__).resolve().parents[1] / "osint_regex" / "__init__.py"
    spec = importlib.util.spec_from_file_location(
        "osint_regex",
        module_path,
        submodule_search_locations=[str(module_path.parent)],
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    module.__dict__.update(
        {
            "_validate_domain": _validate_domain,
            "_validate_ipv4": _validate_ipv4,
            "_validate_ipv6": _validate_ipv6,
            "_validate_cidr": _validate_cidr,
            "_validate_uuid": _validate_uuid,
            "_validate_phone_e164": _validate_phone_e164,
            "_validate_onion_address": _validate_onion_address,
            "_validate_bitcoin_cash_wallet": _validate_bitcoin_cash_wallet,
            "_validate_tron": _validate_tron,
            "_validate_solana": _validate_solana,
        }
    )
    sys.modules.pop("osint_regex", None)
    sys.modules["osint_regex"] = module
    spec.loader.exec_module(module)
    return module


osreg = _load_osint_regex()


CANONICAL_CASES = [
    ("email", "Reach info@example.com.", ["info@example.com"]),
    (
        "website",
        "Visit https://www.example.com/about?x=1#y.",
        ["https://www.example.com/about?x=1#y"],
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
    (
        "cardano_wallet",
        "Cardano addr1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0yu80w.",
        ["addr1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0yu80w"],
    ),
    ("doge_wallet", f"Doge D{'A' * 33}.", [f"D{'A' * 33}"]),
    ("litecoin_wallet", f"Litecoin L{'1' * 26}.", [f"L{'1' * 26}"]),
    ("ripple_wallet", f"Ripple r{'A' * 33}.", [f"r{'A' * 33}"]),
    ("stellar_wallet", f"Stellar G{'A' * 40}.", [f"G{'A' * 40}"]),
    ("transaction_hash", f"Hash {'a' * 64}.", ["a" * 64]),
    (
        "price",
        "Prices: USD 10.00, 10 USD, and \u20ac12.50.",
        ["USD 10.00", "10 USD", "\u20ac12.50"],
    ),
    ("latlon", "Coordinates: 48.8584, 2.2945.", [("48.8584", "2.2945")]),
    ("long_string", "OpaqueValue_1234567890", ["OpaqueValue_1234567890"]),
    ("domain", "Domain example.com appears here.", ["example.com"]),
    ("ipv4", "IPv4 192.0.2.1 is a documentation address.", ["192.0.2.1"]),
    ("ipv6", "IPv6 2001:db8::1 is a documentation address.", ["2001:db8::1"]),
    (
        "cidr",
        "CIDR ranges 192.0.2.0/24 and 2001:db8::/32 are documentation prefixes.",
        ["192.0.2.0/24", "2001:db8::/32"],
    ),
    (
        "uuid",
        "UUID 550e8400-e29b-41d4-a716-446655440000 is canonical.",
        ["550e8400-e29b-41d4-a716-446655440000"],
    ),
    (
        "phone_e164",
        "Call +1-201-555-0123 for support.",
        ["+12015550123"],
    ),
    (
        "onion_address",
        "Tor pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion.",
        ["pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"],
    ),
    (
        "bitcoin_cash_wallet",
        "BCH bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy.",
        ["bitcoincash:qp3wjpa3tjlj042z2wv7hahsldgwhwy0rq9sywjpyy"],
    ),
    (
        "cardano_stake_address",
        "Stake stake1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0yu80u.",
        ["stake1vpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5eg0yu80u"],
    ),
    (
        "tron_wallet",
        "TRON TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL is a sample address.",
        ["TNPeeaaFB7K9cmo4uQpcU32zGK8G1NYqeL"],
    ),
    (
        "solana_wallet",
        "Solana 11111111111111111111111111111111 is the system program.",
        ["11111111111111111111111111111111"],
    ),
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
    ("cardano_wallet", "Cardano addr_test0abc123."),
    ("doge_wallet", f"Doge E{'A' * 33}."),
    ("litecoin_wallet", f"Litecoin O{'1' * 26}."),
    ("ripple_wallet", f"Ripple s{'A' * 33}."),
    ("stellar_wallet", f"Stellar H{'A' * 40}."),
    ("transaction_hash", f"Hash {'g' * 64}."),
    ("price", "The amount is 10.00."),
    ("latlon", "Coordinates: 91.0000, 181.0000."),
    ("long_string", "a" * 19),
    ("domain", "Hostname example is missing a dot."),
    ("ipv4", "IPv4 999.0.0.1 is invalid."),
    ("ipv6", "IPv6 2001:db8:::1 is invalid."),
    ("cidr", "CIDR 192.0.2.0/33 is invalid."),
    ("uuid", "UUID 550e8400-e29b-41d4-a716-44665544000Z is invalid."),
    ("phone_e164", "Call +0123456789 for support."),
    (
        "onion_address",
        "Tor pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscr8d.onion.",
    ),
    (
        "bitcoin_cash_wallet",
        "BCH bitcoincash:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzi.",
    ),
    ("cardano_stake_address", "Stake stake_test0abc123 is invalid."),
    ("tron_wallet", "TRON T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWw0 is invalid."),
    ("solana_wallet", "Solana 1111111111111111111111111111111 is too short."),
]


ALIAS_CASES = [
    ("email", "find_emails"),
    ("website", "find_websites"),
    ("website", "url"),
    ("domain", "hostname"),
    ("phone", "find_phone_numbers"),
    ("phone_e164", "tel"),
    ("btc_wallet", "find_btc_wallets"),
    ("bitcoin_cash_wallet", "bch_wallet"),
    ("cardano_wallet", "cardano_payment_address"),
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


def test_find_raises_for_unknown_kind():
    with pytest.raises(KeyError, match="Unknown extraction kind"):
        osreg.find("text", "does_not_exist")


@pytest.mark.parametrize("kind,alias", ALIAS_CASES)
def test_find_accepts_aliases(kind, alias):
    text = SAMPLES[kind]

    assert osreg.find(text, alias) == getattr(osreg, kind)(text)
    assert getattr(osreg, alias)(text) == getattr(osreg, kind)(text)


def test_find_normalizes_kind_names():
    assert osreg.find(SAMPLES["phone_e164"], "  PHONE_E164  ") == osreg.phone_e164(
        SAMPLES["phone_e164"]
    )
    assert osreg.find(SAMPLES["domain"], "  HOSTNAME  ") == osreg.domain(
        SAMPLES["domain"]
    )


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
        "phone_e164",
        "domain",
        "ipv4",
        "ipv6",
        "cidr",
        "uuid",
        "onion_address",
        "bitcoin_cash_wallet",
        "cardano_stake_address",
        "tron_wallet",
        "solana_wallet",
        "url",
        "hostname",
        "bch_wallet",
        "cardano_payment_address",
        "tel",
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
    text = " ".join(
        [
            SAMPLES["email"],
            SAMPLES["phone"],
            SAMPLES["domain"],
            SAMPLES["phone_e164"],
            SAMPLES["btc_wallet"],
            SAMPLES["tron_wallet"],
            SAMPLES["solana_wallet"],
        ]
    )

    assert wrapper.email(text) == osreg.email(text)
    assert wrapper.domain(text) == osreg.domain(text)
    assert wrapper.phone_e164(text) == osreg.phone_e164(text)
    assert wrapper.find(text, "email") == osreg.find(text, "email")
    assert wrapper.scan(text) == osreg.scan(text)
