"""Package-level regex extractors for OSINT-style text mining.

Import the package as ``import osint_regex as osreg`` and use the module-level
helpers directly:

* ``osreg.email(text)``
* ``osreg.phone(text)``
* ``osreg.find(text, "phone")``
* ``osreg.scan(text)``

The implementation is registry-driven so the public API stays compact while
the extractors remain easy to extend and document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, Optional, Pattern

__version__ = "0.2.0"

MatchExtractor = Callable[[re.Match[str]], Optional[Any]]


@dataclass(frozen=True)
class ExtractorSpec:
    """Registry entry describing one extraction category."""

    name: str
    pattern: Pattern[str]
    extract: MatchExtractor
    aliases: tuple[str, ...] = ()


def _clean_text(value: str) -> str:
    return value.rstrip(".,;:!?)]}")


def _full_match(match: re.Match[str]) -> str:
    return _clean_text(match.group(0))


def _twitter_handle(match: re.Match[str]) -> str:
    return match.group(1)


def _phone_number(match: re.Match[str]) -> str | None:
    value = _clean_text(match.group(0))
    digits = re.sub(r"\D", "", value)
    if not 10 <= len(digits) <= 15:
        return None
    if re.fullmatch(r"\d{4}[-/.]\d{2}[-/.]\d{2}", value):
        return None
    return value


def _latlon(match: re.Match[str]) -> tuple[str, str]:
    return match.group(1), match.group(2)


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
TWITTER_PATTERN = re.compile(r"(?<!\w)@([A-Za-z0-9_]{1,15})\b")
BTC_PATTERN = re.compile(
    r"\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"
)
ETH_PATTERN = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
MONERO_PATTERN = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
DASH_PATTERN = re.compile(r"\bX[1-9A-HJ-NP-Za-km-z]{33}\b")
CARDANO_PATTERN = re.compile(r"\baddr1[a-z0-9]+\b")
DOGE_PATTERN = re.compile(r"\bD[a-zA-Z0-9_.-]{33}\b")
LITECOIN_PATTERN = re.compile(r"\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b")
RIPPLE_PATTERN = re.compile(r"\br[0-9a-zA-Z]{33}\b")
STELLAR_PATTERN = re.compile(r"\bG[0-9A-Z]{40,60}\b")
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
        ("websites", "find_websites"),
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
        ("cardano_wallets", "find_cardano_wallets"),
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
        Canonical kind name such as ``"phone"`` or a legacy alias such as
        ``"find_phone_numbers"``.

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
