"""Package-level regex extractors for OSINT-style text mining.

Import the package as ``import osint_regex as osreg`` and use the module-level
helpers directly:

* ``osreg.email(text)``
* ``osreg.phone(text)``
* ``osreg.find(text, "phone")``
* ``osreg.scan(text)``

The implementation is registry-driven so the public API stays compact while
the extractors remain easy to extend and document. A few categories are
intentionally heuristic: regexes act as lightweight prefilters and stdlib
validators are used where they improve signal without adding dependencies.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import uuid as uuid_module
from dataclasses import dataclass
from functools import partial, wraps
from typing import Any, Callable, Match, Optional, Pattern

__version__ = "0.2.1"

MatchExtractor = Callable[[Match[str]], Optional[Any]]

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_INDEX = {char: idx for idx, char in enumerate(_BASE58_ALPHABET)}


@dataclass(frozen=True)
class ExtractorSpec:
    """Registry entry describing one extraction category."""

    name: str
    pattern: Pattern[str]
    extract: MatchExtractor
    aliases: tuple[str, ...] = ()


def _clean_text(value: str) -> str:
    return value.rstrip(".,;:!?)]}")


def _full_match(match: Match[str]) -> str:
    return _clean_text(match.group(0))


def _twitter_handle(match: Match[str]) -> str:
    return match.group(1)


def _extract_if(match: Match[str], validator: Callable[[str], Any]) -> str | None:
    value = _clean_text(match.group(0))
    result = validator(value)
    if isinstance(result, str):
        return result
    return value if result else None


def _phone_number(match: Match[str]) -> str | None:
    value = _clean_text(match.group(0))
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 15:
        return None
    if re.fullmatch(r"\d{4}[-/.]\d{2}[-/.]\d{2}", value):
        return None
    return value


def _validate_phone_e164(value: str) -> str | None:
    digits = re.sub(r"\D", "", value)
    if not 8 <= len(digits) <= 15:
        return None
    if digits[0] == "0":
        return None
    return f"+{digits}"


def _latlon(match: Match[str]) -> tuple[str, str]:
    return match.group(1), match.group(2)


def _base58_decode(value: str) -> bytes:
    total = 0
    for char in value:
        try:
            total = total * 58 + _BASE58_INDEX[char]
        except KeyError as exc:
            raise ValueError(f"Invalid base58 character: {char!r}") from exc
    raw = total.to_bytes((total.bit_length() + 7) // 8, "big") if total else b""
    pad = len(value) - len(value.lstrip("1"))
    return b"\x00" * pad + raw


def _base58check_decode(value: str) -> bytes:
    decoded = _base58_decode(value)
    if len(decoded) < 4:
        raise ValueError("Base58Check payload is too short")
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if checksum != expected:
        raise ValueError("Invalid Base58Check checksum")
    return payload


def _validate_domain(value: str) -> bool:
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


def _validate_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _validate_ipv6(value: str) -> bool:
    candidate = value.split("%", 1)[0]
    try:
        ipaddress.IPv6Address(candidate)
        return True
    except ValueError:
        return False


def _validate_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _validate_uuid(value: str) -> str | None:
    try:
        return str(uuid_module.UUID(value))
    except ValueError:
        return None


def _validate_onion_address(value: str) -> bool:
    candidate = value.lower()
    if not candidate.endswith(".onion"):
        return False
    host = candidate[:-6]
    if len(host) != 56:
        return False
    return all(char in "abcdefghijklmnopqrstuvwxyz234567" for char in host)


_CASHADDR_ALPHABET = set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
_CASHADDR_PREFIXES = {"bitcoincash", "bchtest", "bchreg"}


def _validate_bitcoin_cash_wallet(value: str) -> bool:
    prefix, sep, payload = value.partition(":")
    if not sep:
        return False
    if prefix.lower() not in _CASHADDR_PREFIXES:
        return False
    payload = payload.lower()
    if len(payload) < 20:
        return False
    return all(char in _CASHADDR_ALPHABET for char in payload)


def _validate_tron(value: str) -> bool:
    if not re.fullmatch(r"T[1-9A-HJ-NP-Za-km-z]{33}", value):
        return False
    try:
        payload = _base58check_decode(value)
    except ValueError:
        return False
    return len(payload) == 21 and payload.startswith(b"\x41")


def _validate_solana(value: str) -> bool:
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", value):
        return False
    try:
        decoded = _base58_decode(value)
    except ValueError:
        return False
    return len(decoded) == 32


DOMAIN_EXTRACT = partial(_extract_if, validator=_validate_domain)
IPV4_EXTRACT = partial(_extract_if, validator=_validate_ipv4)
IPV6_EXTRACT = partial(_extract_if, validator=_validate_ipv6)
CIDR_EXTRACT = partial(_extract_if, validator=_validate_cidr)
UUID_EXTRACT = partial(_extract_if, validator=_validate_uuid)
PHONE_E164_EXTRACT = partial(_extract_if, validator=_validate_phone_e164)
ONION_EXTRACT = partial(_extract_if, validator=_validate_onion_address)
BCH_EXTRACT = partial(_extract_if, validator=_validate_bitcoin_cash_wallet)
TRON_EXTRACT = partial(_extract_if, validator=_validate_tron)
SOLANA_EXTRACT = partial(_extract_if, validator=_validate_solana)


def _extract_all(text: str, spec: ExtractorSpec) -> list[Any]:
    results: list[Any] = []
    for match in spec.pattern.finditer(text):
        value = spec.extract(match)
        if value is not None:
            results.append(value)
    return results


EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
WEBSITE_PATTERN = re.compile(
    r"""
    (?<!@)
    \b
    (?:
        https?://
        |
        www\.
    )?
    [A-Za-z0-9.-]+\.[A-Za-z]{2,}
    (?:/[^\s<>"']*)?
    """,
    re.VERBOSE | re.IGNORECASE,
)
DOMAIN_PATTERN = re.compile(
    r"""
    (?<!@)
    (?<!://)
    \b
    [A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
    (?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+
    \b
    """,
    re.VERBOSE | re.IGNORECASE,
)
IPV4_PATTERN = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?![\d/])")
IPV6_PATTERN = re.compile(r"(?<![\w])(?=[0-9A-Fa-f:.]*:)[0-9A-Fa-f:.]{2,}(?![\w])")
CIDR_PATTERN = re.compile(r"(?<![\w])(?:[0-9A-Fa-f:.]+/\d{1,3})(?![\w])")
UUID_PATTERN = re.compile(
    r"\b[0-9A-Fa-f]{8}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{12}\b"
)
PHONE_PATTERN = re.compile(
    r"""
    (?<!\w)
    (?:
        \+?\d[\d\s().-]{8,}\d
        |
        \(\d{2,4}\)[\d\s().-]{7,}\d
        |
        \+?\d{10,15}
    )
    (?!\w)
    """,
    re.VERBOSE,
)
PHONE_E164_PATTERN = re.compile(
    r"""
    (?<!\w)
    \+
    [\d\s().-]{6,18}\d
    (?!\w)
    """,
    re.VERBOSE,
)
TWITTER_PATTERN = re.compile(r"(?<!\w)@([A-Za-z0-9_]{1,15})\b")
BTC_PATTERN = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
MONERO_PATTERN = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
DASH_PATTERN = re.compile(r"\bX[1-9A-HJ-NP-Za-km-z]{33}\b")
CARDANO_PATTERN = re.compile(r"\baddr(?:_test)?1[a-z0-9]+\b", re.IGNORECASE)
CARDANO_STAKE_PATTERN = re.compile(
    r"\bstake(?:_test)?1[a-z0-9]+\b",
    re.IGNORECASE,
)
DOGE_PATTERN = re.compile(r"\bD[a-zA-Z0-9_.-]{33}\b")
LITECOIN_PATTERN = re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b")
RIPPLE_PATTERN = re.compile(r"\br[0-9a-zA-Z]{33}\b")
STELLAR_PATTERN = re.compile(r"\bG[0-9A-Z]{40,60}\b")
ONION_PATTERN = re.compile(r"\b[a-z2-7]{56}\.onion\b", re.IGNORECASE)
BCH_PATTERN = re.compile(
    r"\b(?:bitcoincash|bchtest|bchreg):[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,}\b",
    re.IGNORECASE,
)
TRON_PATTERN = re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
SOLANA_PATTERN = re.compile(r"\b[1-9A-HJ-NP-Za-km-z]{32,44}\b")
TX_HASH_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")
PRICE_PATTERN = re.compile(
    r"""
    (?<!\w)
    (?:
        (?:USD|EUR|\u20ac|\$)\s?\d+(?:[.,]\d{3})*(?:[.,]\d{2})?
        |
        \d+(?:[.,]\d{3})*(?:[.,]\d{2})?\s?(?:USD|EUR|\u20ac|\$)
    )
    (?!\w)
    """,
    re.VERBOSE,
)
LATLON_PATTERN = re.compile(
    r"""
    (?<!\d)
    ([-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))
    \s*,\s*
    ([-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|[1-9]?\d)(?:\.\d+)?))
    (?!\d)
    """,
    re.VERBOSE,
)
LONG_STRING_PATTERN = re.compile(r"\b[a-zA-Z0-9_.-]{20,}\b")


_SPECS: tuple[ExtractorSpec, ...] = (
    ExtractorSpec("email", EMAIL_PATTERN, _full_match, ("emails", "find_emails")),
    ExtractorSpec(
        "website",
        WEBSITE_PATTERN,
        _full_match,
        ("websites", "url", "urls", "find_url", "find_urls", "find_websites"),
    ),
    ExtractorSpec(
        "phone",
        PHONE_PATTERN,
        _phone_number,
        (
            "phone_number",
            "phones",
            "phone_numbers",
            "find_phone_number",
            "find_phones",
            "find_phone_numbers",
        ),
    ),
    ExtractorSpec(
        "twitter_handle",
        TWITTER_PATTERN,
        _twitter_handle,
        ("twitter_handles", "find_twitter_handles"),
    ),
    ExtractorSpec(
        "btc_wallet",
        BTC_PATTERN,
        _full_match,
        ("btc_wallets", "find_btc_wallets"),
    ),
    ExtractorSpec(
        "eth_wallet",
        ETH_PATTERN,
        _full_match,
        ("eth_wallets", "find_eth_wallets"),
    ),
    ExtractorSpec(
        "monero_wallet",
        MONERO_PATTERN,
        _full_match,
        ("monero_wallets", "find_monero_wallets"),
    ),
    ExtractorSpec(
        "dash_wallet",
        DASH_PATTERN,
        _full_match,
        ("dash_wallets", "find_dash_wallets"),
    ),
    ExtractorSpec(
        "cardano_wallet",
        CARDANO_PATTERN,
        _full_match,
        (
            "cardano_wallets",
            "cardano_payment_address",
            "find_cardano_wallets",
            "find_cardano_payment_address",
        ),
    ),
    ExtractorSpec(
        "doge_wallet",
        DOGE_PATTERN,
        _full_match,
        ("doge_wallets", "find_doge_wallets"),
    ),
    ExtractorSpec(
        "litecoin_wallet",
        LITECOIN_PATTERN,
        _full_match,
        ("litecoin_wallets", "find_litecoin_wallets"),
    ),
    ExtractorSpec(
        "ripple_wallet",
        RIPPLE_PATTERN,
        _full_match,
        ("ripple_wallets", "find_ripple_wallets"),
    ),
    ExtractorSpec(
        "stellar_wallet",
        STELLAR_PATTERN,
        _full_match,
        ("stellar_wallets", "find_stellar_wallets"),
    ),
    ExtractorSpec(
        "transaction_hash",
        TX_HASH_PATTERN,
        _full_match,
        ("transaction_hashes", "find_transaction_hashes"),
    ),
    ExtractorSpec("price", PRICE_PATTERN, _full_match, ("prices", "find_prices")),
    ExtractorSpec(
        "latlon",
        LATLON_PATTERN,
        _latlon,
        ("latlon_pairs", "find_latlon"),
    ),
    ExtractorSpec(
        "long_string",
        LONG_STRING_PATTERN,
        _full_match,
        ("long_strings", "find_long_strings"),
    ),
    ExtractorSpec(
        "domain",
        DOMAIN_PATTERN,
        DOMAIN_EXTRACT,
        (
            "domains",
            "hostname",
            "hostnames",
            "find_domain",
            "find_domains",
            "find_hostname",
            "find_hostnames",
        ),
    ),
    ExtractorSpec(
        "ipv4",
        IPV4_PATTERN,
        IPV4_EXTRACT,
        (
            "ipv4_address",
            "ipv4_addresses",
            "find_ipv4",
            "find_ipv4_address",
            "find_ipv4_addresses",
        ),
    ),
    ExtractorSpec(
        "ipv6",
        IPV6_PATTERN,
        IPV6_EXTRACT,
        (
            "ipv6_address",
            "ipv6_addresses",
            "find_ipv6",
            "find_ipv6_address",
            "find_ipv6_addresses",
        ),
    ),
    ExtractorSpec(
        "cidr",
        CIDR_PATTERN,
        CIDR_EXTRACT,
        (
            "cidr_block",
            "cidr_blocks",
            "find_cidr",
            "find_cidr_block",
            "find_cidr_blocks",
        ),
    ),
    ExtractorSpec(
        "uuid",
        UUID_PATTERN,
        UUID_EXTRACT,
        ("uuids", "find_uuid", "find_uuids"),
    ),
    ExtractorSpec(
        "phone_e164",
        PHONE_E164_PATTERN,
        PHONE_E164_EXTRACT,
        ("tel", "phone_e164s", "find_tel", "find_phone_e164", "find_phone_e164s"),
    ),
    ExtractorSpec(
        "onion_address",
        ONION_PATTERN,
        ONION_EXTRACT,
        (
            "onion",
            "onions",
            "onion_addresses",
            "find_onion",
            "find_onions",
            "find_onion_addresses",
        ),
    ),
    ExtractorSpec(
        "bitcoin_cash_wallet",
        BCH_PATTERN,
        BCH_EXTRACT,
        (
            "bch_wallet",
            "bch_wallets",
            "find_bch_wallet",
            "find_bch_wallets",
        ),
    ),
    ExtractorSpec(
        "cardano_stake_address",
        CARDANO_STAKE_PATTERN,
        _full_match,
        (
            "cardano_stake_addresses",
            "find_cardano_stake_address",
            "find_cardano_stake_addresses",
        ),
    ),
    ExtractorSpec(
        "tron_wallet",
        TRON_PATTERN,
        TRON_EXTRACT,
        (
            "tron_address",
            "tron_addresses",
            "find_tron_address",
            "find_tron_addresses",
        ),
    ),
    ExtractorSpec(
        "solana_wallet",
        SOLANA_PATTERN,
        SOLANA_EXTRACT,
        (
            "solana_address",
            "solana_addresses",
            "find_solana_address",
            "find_solana_addresses",
        ),
    ),
)

_SPEC_BY_NAME = {spec.name: spec for spec in _SPECS}
_ALIASES = {alias: spec.name for spec in _SPECS for alias in (spec.name, *spec.aliases)}
_PUBLIC_NAMES = [spec.name for spec in _SPECS]


def _resolve_kind(kind: str) -> ExtractorSpec:
    key = kind.strip().lower()
    try:
        return _SPEC_BY_NAME[_ALIASES[key]]
    except KeyError as exc:
        available = ", ".join(_PUBLIC_NAMES)
        raise KeyError(
            f"Unknown extraction kind {kind!r}. Available kinds: {available}"
        ) from exc


def find(text: str, kind: str) -> list[Any]:
    """Return matches for one extraction kind.

    Parameters
    ----------
    text:
        Decoded text to inspect.
    kind:
        Canonical kind name such as ``"phone"`` or a compatibility alias such
        as ``"find_phone_numbers"`` or ``"url"``.

    Returns
    -------
    list[Any]
        The extracted matches for that category. Structured outputs such as
        latitude/longitude pairs are returned as tuples.

    Raises
    ------
    KeyError
        Raised when ``kind`` does not map to a known extractor.
    """

    return _extract_all(text, _resolve_kind(kind))


def scan(text: str) -> dict[str, list[Any]]:
    """Return every category and its matches in a stable order.

    The returned dictionary always includes every canonical category, even when
    the value is an empty list.
    """

    return {spec.name: _extract_all(text, spec) for spec in _SPECS}


def _make_helper(target: str) -> Callable[[str], list[Any]]:
    @wraps(find)
    def helper(text: str) -> list[Any]:
        return find(text, target)

    helper.__name__ = target
    helper.__qualname__ = target
    helper.__doc__ = (
        f"Return matches for the {target.replace('_', ' ')} category.\n\n"
        f"This helper is generated from the extractor registry and is equivalent "
        f"to calling find(text, {target!r})."
    )
    return helper


for _name in _PUBLIC_NAMES:
    globals()[_name] = _make_helper(_name)

for _alias in sorted({alias for spec in _SPECS for alias in spec.aliases}):
    globals()[_alias] = _make_helper(_ALIASES[_alias])


class OSINTRegex:
    """Compatibility wrapper exposing the module-level helpers as methods.

    Prefer the module-level helpers for new code. This class is kept so older
    call sites can continue to instantiate ``OSINTRegex`` without a breaking
    change.
    """

    __slots__ = ()

    find = staticmethod(find)
    scan = staticmethod(scan)


for _name in _PUBLIC_NAMES:
    setattr(OSINTRegex, _name, staticmethod(globals()[_name]))

for _alias in sorted({alias for spec in _SPECS for alias in spec.aliases}):
    setattr(OSINTRegex, _alias, staticmethod(globals()[_alias]))


__all__ = [
    "OSINTRegex",
    "__version__",
    "find",
    "scan",
]

__all__.extend(_PUBLIC_NAMES)
__all__.extend(sorted({alias for spec in _SPECS for alias in spec.aliases}))
